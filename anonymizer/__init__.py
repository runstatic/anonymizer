# -*- coding: utf-8 -*-

"""Python script containing the definitions of the classes Anonymizer and InitializationException."""

import json
from anonymizer.operators import AnonymizationOperators


class InitializationException(Exception):
    """Raised for any Exception that do not allow the creation of the anonymizer instance."""


class Anonymizer:
    """
    Anonymizer contains method for anonymizing JSON given the corresponding json-schema.

    Methods
    -------
    anonymize_json(target_json)
        Anonymize the json dictionary accordingly to the rules specified in the json-schema
    anonymize_json_str(target_json_str)
        Anonymize the json string accordingly to the rules specified in the json-schema

    The json-schema of the field to be anonymized must have the additional attributes: x-anonymize-operation and
    x-anonymize-args, specifying the anonymization operation to apply and its args.
    For more information please refer to the README.md.
    """

    json_schema_str = None
    json_schema = None
    anonymization_operators = None

    ALL_ELEMENTS_IN_ARRAY_NOTATION = "[*]"

    def _apply_function_by_path(
        self, current_json_subtree, path_chunks, target_function, function_args
    ):
        """
        Recursive functions applying the target functions to the the fields matching the path in the JSON.

        :param current_json_subtree:
        :param path_chunks:
        :param target_function:
        :return: current_json_subtree with function applied on it
        """
        if not current_json_subtree:
            # subtree is null or empty
            # we can't proceed further
            # since the element does not exist, return successfully
            return True
        if len(path_chunks) == 1:
            # base case: we reached the end of the path - set the new value
            if path_chunks[0] == self.ALL_ELEMENTS_IN_ARRAY_NOTATION and isinstance(
                current_json_subtree, list
            ):
                # apply function to each element of the list
                for i, list_item_value in enumerate(current_json_subtree):
                    current_json_subtree[i] = target_function(
                        list_item_value, *function_args
                    )
            else:
                # apply function to the single item
                if path_chunks[0] in current_json_subtree:
                    current_value = current_json_subtree[path_chunks[0]]
                    current_json_subtree[path_chunks[0]] = target_function(
                        current_value, *function_args
                    )
            return True
        else:
            for k in path_chunks[:-1]:
                if k == self.ALL_ELEMENTS_IN_ARRAY_NOTATION:
                    for sub_json_item in current_json_subtree:
                        self._apply_function_by_path(
                            sub_json_item,
                            path_chunks[1:],
                            target_function,
                            function_args,
                        )
                    return True
                elif k in current_json_subtree:
                    next_subtree = current_json_subtree[k]
                    done = self._apply_function_by_path(
                        next_subtree, path_chunks[1:], target_function, function_args
                    )
                    if done:
                        return True

    def _find_fields_to_anonymize_from_schema(
        self, root: dict, traversed_path, fields_to_anonymize
    ):
        """
        Recursive function to traverse the json-schema dictionary looking for fields to anonymize.

        :param root: python dictionary representing the root of the tree
        :param traversed_path: tmp list useful during recursion calls to track the traversed path, empty initially
        :param fields_to_anonymize: tmp list useful during recursion calls to store the target paths, empty initially
        :return: list of dictionaries representing the fields to anonymize, containing the path, operation, tags
        """
        if "x-anonymize-operation" in root.keys():
            # base-case
            field_to_anonymize = {
                "path": traversed_path,
                "operation": root["x-anonymize-operation"],
                "args": root.get("x-anonymize-args", []),
            }
            fields_to_anonymize.append(field_to_anonymize)
        if not len(root.keys()) == 0:
            # recursive case
            for key in root.keys():
                if type(root[key]) is dict:
                    new_root = root[key]
                    new_traversed_path = traversed_path

                    """
                    We want to keep track of the traversed keys inside the list new_traversed path.
                    However, while traversing the json-schema we also store json-schema schema related keys like:
                    properties or items. A simple path like /user/id it is actually tracked by the traversed json-schema
                    keys /properties/user/properties/id. The conditions below are intended to handle those json-schema
                    specific keys, skipping the key 'properties' and replacing the 'items' with
                    the constant ALL_ELEMENTS_IN_ARRAY_NOTATION.
                    """

                    if (
                        key == "properties"
                        and "type" in root
                        and (
                            (type(root["type"]) is list and "object" in root["type"])
                            or root["type"] == "object"
                        )
                    ):
                        pass  # if traverse json-schema related keys like properties just continue
                    else:
                        if (
                            key == "items"
                            and "type" in root
                            and (
                                (type(root["type"]) is list and "array" in root["type"])
                                or root["type"] == "array"
                            )
                        ):
                            # if traverse items of an array, replace the key with [*]
                            key = self.ALL_ELEMENTS_IN_ARRAY_NOTATION
                        new_traversed_path = traversed_path + [
                            key
                        ]  # create a new list, so that it is passed by copy

                    self._find_fields_to_anonymize_from_schema(
                        new_root, new_traversed_path, fields_to_anonymize
                    )
        return fields_to_anonymize

    def __init__(self, json_schema=None, json_schema_str=None, encryption_secret=None):
        """
        Create the Anonymizer with the specified schema.

        JSON schema can be specified in a dictionary format using the parameter :json_schema or string format
        using the parameter :json_schema_str.

        :param json_schema: json-schema dictionary
        :param json_schema_str: json schema as string
        :param encryption_secret: secret used by the operation 'encrypt'
        """
        if not json_schema and not json_schema_str:
            raise InitializationException(
                "You need to specify the schema using json_schema or json_schema_str params"
            )

        if not json_schema:
            self.json_schema_str = json_schema_str
            self.json_schema = json.loads(json_schema_str)
        else:
            self.json_schema = json_schema
        self.anonymization_operators = AnonymizationOperators(
            encryption_secret=encryption_secret
        )

        # passing empty lists for initializing the recursive function, default parameters mess up things
        self.fields_to_anonymize = self._find_fields_to_anonymize_from_schema(
            self.json_schema, [], []
        )

    def anonymize_json(self, target_json):
        """
        Anonymize the json dictionary accordingly to the rules specified in the json-schema.

        :param target_json: target json as dictionary
        :return: dictionary representing the anonymized json
        """
        for field_to_anonymize in self.fields_to_anonymize:
            # read path, and anonymization operation and args
            path_chunks = field_to_anonymize["path"]
            anonymization_operation_str = field_to_anonymize["operation"]
            operation_args = field_to_anonymize.get("args")

            # get anonymization operation
            anonymization_operation = getattr(
                self.anonymization_operators, anonymization_operation_str
            )

            # apply function to all the fields matching the path
            self._apply_function_by_path(
                target_json, path_chunks, anonymization_operation, operation_args
            )

        return target_json

    def anonymize_json_str(self, target_json_str):
        """
        Anonymize the json string accordingly to the rules specified in the json-schema.

        :param target_json_str: target json as string
        :return: dictionary representing the anonymized json
        """
        target_json = json.loads(target_json_str)
        return self.anonymize_json(target_json)
