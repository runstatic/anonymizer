# -*- coding: utf-8 -*-

"""This script contains the AnonymizationOperators class, container for all the anonymization operators."""
from typing import Union

from anonymizer.encryption import SymmetricEncryption
import numbers
import datetime
import re
import builtins
import operator
import json
import glom


class AnonymizationOperators:
    """
    AnonymizationOperators contains all the anonymization operators.

    All the operators' output preserve the input data type (or return None). To enforce this,
    we are returning boolean type wrapped in a string or with its integer representation (eg. is_string_present)

    Methods
    -------
    round_ip(field_value)
        Round IP address putting the last two numbers to 0.
    put_to_null(field_value)
        Return None regardless the input value.
    round_float_to_integer(field_value)
        Round the input float to the closest integer.
    round_float(field_value, ndigits)
        Round float to ndigits decimal digits.
    encrypt(field_value)
        Encrypt the field using the encryption secret
    is_string_present(field_value)
        Return "false" if :field_value is empty, white-spaces, null or not a String; "true" otherwise.
    is_number_present(field_value)
        Return 0 if :field_value is null or not a number, 1 otherwise.
    is_email_present_or_test(field_value, test_domains)
        Return a string representing the existence of the email (true, false, invalid, test)
    is_slug_present_or_test(field_value)
        Return a string representing the existence of the slug (true, false, test)
    truncate_day_from_str(field_value, pattern)
        Return the given date with its day set to first of the month and the time part zeroed.
    truncate_day_from_posix_timestamp(field_value)
        Return the given :posix_timestamp with its day set to first of the month and the time part zeroed.
    truncate_day_from_epoch_milliseconds(field_value)
        Return the given :milliseconds_since_epoch with its day set to first of the month and the time part zeroed.
    replace_regex_matches_with_string(field_value, pattern, repl)
        Return the string obtained by replacing the occurrences of :pattern in :field_value by the replacement :repl.
    conditional_operation(field_dict, conditional_args)
        Return the dictionary with replaced field value if: condition is met, unchanged dictionary otherwise.
    split_anonymize_and_join(field_value, anonymize_args)
        Return the string with replaced separated values.
    apply_function_on_field_in_json_string(field_value, anonymize_args)
        Return a string representation of a json object after applying a function to one of its fields.
    serialize_to_json_string(field_value)
        Serialize the field :field_value to JSON string.
    convert_to_field_length(field_value)
        Return the length of :field_value (string/array).
    """

    symmetric_encryptor = None

    def __init__(self, encryption_secret=None):
        """
        Initialize the AnonymizationOperators.

        :param encryption_secret: secret used by the encrypt operation
        """
        if encryption_secret:
            self.symmetric_encryptor = SymmetricEncryption(encryption_secret)

    def round_ip(self, field_value: str):
        """
        Round IP address putting the last two numbers to 0.

        :param field_value: string representing an IP address
        :return: rounded IP
        """
        if field_value is None:
            return None
        ip_parts = field_value.split(".")
        return "{}.{}.0.0".format(ip_parts[0], ip_parts[1])

    def put_to_null(self, field_value):
        """
        Return None regardless the input value.

        :param field_value: element we want to replace
        :return: None
        """
        return None

    def round_float_to_integer(self, field_value: float):
        """
        Round the input float to the closest integer.

        :param field_value: element we want to replace
        :return: None
        """
        if field_value is None:
            return None
        return int(round(field_value))

    def round_float(self, field_value: float, ndigits: int):
        """
        Round float to ndigits decimal digits.

        :param field_value: input float value
        :param ndigits: number of digits to round to
        :return: float rounded to ndigits decimals
        """
        if field_value is None:
            return None
        return round(field_value, ndigits=ndigits)

    def encrypt(self, field_value):
        """
        Encrypt the field using the encryption secret.

        :return: encrypted field
        """
        if field_value is None:
            return None
        if not self.symmetric_encryptor:
            raise Exception("Encryption secret not set")
        # cast to string, e.g. for ids that come as type integer
        field_value = str(field_value)
        return self.symmetric_encryptor.encrypt(field_value)

    def decrypt(self, field_value):
        """
        Decrypt the field using the encryption secret.

        :return: decrypted field
        """
        if field_value is None:
            return None
        if not self.symmetric_encryptor:
            raise Exception("Encryption secret not set")
        return self.symmetric_encryptor.decrypt(field_value)

    def is_string_present(self, field_value):
        """
        Return "false" if :field_value is empty, white-spaces, null or not a String; "true" otherwise.

        :return: string representing whether the field is present
        """
        if field_value is None or type(field_value) is not str:
            return "false"
        return "true" if field_value.strip() else "false"

    def is_number_present(self, field_value):
        """
        Return 0 if :field_value is null or not a number, 1 otherwise.

        :return: integer representing whether the field is present
        """
        return (
            1
            if (field_value is not None and isinstance(field_value, numbers.Number))
            else 0
        )

    def convert_to_field_length(self, field_value) -> int:
        """
        Return the length of :field_value.

        :param field_value: input string/array
        :return: integer representing the length of :field_value
        """
        if field_value is None:
            return 0
        return len(field_value)

    def is_email_present_or_test(self, field_value, test_domains):
        """
        Return a string representing the existence of the email (true, false, invalid, test)

        In detail:
         - "false" if value is missing,
         - "true" if value is a valid email address,
         - "test" if value is valid email address and its email domain is in the list of :test_domains
         - "invalid" if value is not valid email after a naive check (does not contain @).

        :return: string representing if :field_value is present or if it is test email
        """
        is_present = self.is_string_present(field_value)
        if is_present == "true":
            if "@" not in field_value:
                # basic check if value is a valid email
                return "invalid"
            domain = (field_value.split("@")[1]).lower().strip()
            test_domains = [test_domain.lower().strip() for test_domain in test_domains]
            if domain in test_domains:
                return "test"
        return is_present

    def truncate_day_from_str(self, date_str, date_pattern):
        """
        Return the given date with its day set to first of the month and the time part zeroed.

        Input :date_str and output follow the :date_pattern
        Reference for :date_pattern https://docs.python.org/3/library/datetime.html#strftime-and-strptime-format-codes

        :return: string representing the input date :date_str with the day set to 1 and with the time zeroed.
        """
        if self.is_string_present(date_pattern) == "false":
            return "invalid_pattern: missing"
        if self.is_string_present(date_str) == "false":
            return None
        try:
            date = datetime.datetime.strptime(date_str, date_pattern)
        except ValueError:
            return "input_does_not_match_pattern: {}".format(date_pattern)
        except Exception as e:
            return "invalid_pattern: {} / error: {}".format(date_pattern, str(e))

        # Apparently, on linux machines the leading zeros are removed for years before 1000 when using %Y formatter.
        # %4Y would solve the problem, however this generates problems on Windows and Mac. That is why we decided to
        # do the formatting of the year manually.
        # https://docs.python.org/dev/library/datetime.html#strftime-strptime-behavior
        anonymized_date = date.replace(day=1, second=0, minute=0, hour=0, microsecond=0)
        date_pattern_year_manually_filled = date_pattern.replace(
            "%Y", f"{anonymized_date.year:04}"
        )
        anonymized_date_str = anonymized_date.strftime(
            date_pattern_year_manually_filled
        )
        return anonymized_date_str

    def truncate_day_from_posix_timestamp(self, posix_timestamp):
        """
        Return the given :posix_timestamp with its day set to first of the month and the time part zeroed.

        The posix timestamp or UNIX timestamp is a number representing seconds since 1970-01-01.

        :return: integer representing the :posix_timestamp of the truncated input date
        """
        if self.is_number_present(posix_timestamp) == 0:
            return None
        try:
            date = datetime.datetime.utcfromtimestamp(posix_timestamp)
        except Exception:
            return None
        truncated_date = date.replace(
            day=1,
            second=0,
            minute=0,
            hour=0,
            microsecond=0,
            tzinfo=datetime.timezone.utc,
        )
        return int(datetime.datetime.timestamp(truncated_date))

    def truncate_day_from_epoch_milliseconds(self, milliseconds_since_epoch):
        """
        Return the given :milliseconds_since_epoch with its day set to first of the month and the time part zeroed.

        :return: integer representing the milliseconds since epoch of the truncated input date
        """
        if self.is_number_present(milliseconds_since_epoch) == 0:
            return None
        seconds_since_epoch = milliseconds_since_epoch / 1000
        truncated_unix_timestamp = self.truncate_day_from_posix_timestamp(
            seconds_since_epoch
        )
        return (
            truncated_unix_timestamp * 1000
            if truncated_unix_timestamp is not None
            else truncated_unix_timestamp
        )

    def replace_regex_matches_with_string(
        self, field_value: str, pattern: str, repl: str
    ):
        """
        Return the string obtained by replacing the occurrences of :pattern in :field_value by the replacement :repl.

        :param field_value: the input string
        :param pattern: string representing the regex matching the substrings to be replaced
        :param repl: the string that is going to take the place of the matching sub-strings
        :return: string with replaced text
        """
        if field_value is None:
            return None
        return re.sub(pattern, repl, field_value)

    def conditional_operation(
        self, field_dict: dict, conditional_args: Union[dict, list]
    ):
        """
        Evaluate condition(s) and apply specified anonymization operation if the condition is met. Also works for
        fields in different layers inside the schema.
        Note: the following parameters must either be all single values or lists of the same length:
            - conditional_fields
            - conditional_field_values_when_null
            - conditional_values
            - conditional_operators

        :param field_dict: dictionary containing the field to apply operation on if condition is met
        :param conditional_args: dictionary or list of dictionaries containing the conditional arguments:
               - function: anonymization operation to perform
               - function_args (optional): additional arguments for the operation to perform (default is empty list)
               - target_field: field inside the dictionary to apply the operation on
               - conditional_fields: str or list of strings, field(s) to evaluate condition on
               - conditional_field_values_when_null: value or list of values, values that should be used if value of
                 conditional_field is None/null (necessary for example when: None < 100 --> will thow an error --> e.g. use 0 < 100)
               - conditional_values: value or list of values, required value(s) in order to perform the anonymization operation
               - conditional_operators: str or list of strings, string(s) representing the conditional operator to apply
               - conditional_boolean_function: used for combination of multiple conditions

        :return: dictionary with replaced field value if: condition is met, unchanged dictionary otherwise

        Examples:
        - single condition: id attribute gets encrypted if type attribute is equal to "user":
            "x-anonymize-operation": "conditional_operation",
            "x-anonymize-args": [{
                "function": "encrypt",
                "target_field": "id",
                "conditional_fields": "type",
                "conditional_field_values_when_null": null,
                "conditional_values": "user",
                "conditional_operators": "=="
            }]

        - combined condition: attributes.name attribute is put to null if type attribute is not equal to
          "random_group" OR "attributes.member_count" attribute is lower than 100:
            "x-anonymize-operation": "conditional_operation",
            "x-anonymize-args": [{
                "function": "put_to_null",
                "target_field": "attributes.name",
                "conditional_fields": ["type", "attributes.member_count"],
                "conditional_field_values_when_null": [null, 0],
                "conditional_values": ["random_group", 100],
                "conditional_operators": ["!=", "<"],
                "conditional_boolean_function": "or"
            }],
        """
        if field_dict is None:
            return None

        def contains_wrapper(a, b):
            """
            Check if a is in b
            :param a: value to search in b
            :param b: any data type an "in" operator can be applied on (e.g. list, tuple, string)
            :return: boolean, whether a is in b or not
            """
            return operator.contains(b, a)

        def not_contains(a, b):
            """
            Check if a is not in b
            :param a: value to search in b
            :param b: any data type an "in" operator can be applied on (e.g. list, tuple, string)
            :return: boolean, if a is in b -> False, True otherwise
            """
            return not contains_wrapper(a, b)

        def evaluate_condition(
            field_dict, cond_field, cond_value, cond_operator, value_when_null
        ):
            """
            Evaluate single condition
            :return: boolean
            """
            path = cond_field.split(".")
            value = field_dict
            for p in path:
                value = value[p]
            if value is None:
                return cond_operator(value_when_null, cond_value)
            else:
                return cond_operator(value, cond_value)

        def ensure_type_list(co):
            """
            Convert input into a list, e.g. "123" -> ["123], ["123", "234"] -> ["123", "234"]
            :return: list
            """
            if not isinstance(co, list):
                return [co], 1
            else:
                return co, len(co)

        def execute_conditional_operator(conditional_args_dict):
            """
            Execute the conditional operation given the conditional arguments.
            :param conditional_args_dict: dictionary containing conditional arguments
            """
            target_field = conditional_args_dict["target_field"]
            # Check if the `target_field` path exists in the `field_dict`. In the previous versions we only checked if
            # the final attribute in the path exists. However, for some messages (e.g. sport_activity) it can happen
            # that a full object is missing. For example, the 'source_content' object in attributes.source_content.id
            # can be missing. In case the path is not valid, the operation will be skipped. This also means that typos
            # in `target_field` are ignored and no error is raised!
            try:
                glom.glom(field_dict, target_field)
            except glom.core.PathAccessError:
                return

            conditional_field_values_when_null, len1 = ensure_type_list(
                conditional_args_dict["conditional_field_values_when_null"]
            )
            conditional_operators, len2 = ensure_type_list(
                conditional_args_dict["conditional_operators"]
            )
            conditional_fields, len3 = ensure_type_list(
                conditional_args_dict["conditional_fields"]
            )
            conditional_values, len4 = ensure_type_list(
                conditional_args_dict["conditional_values"]
            )
            conditional_boolean_function = conditional_args_dict.get(
                "conditional_boolean_function", "and"
            )
            # check if all necessary information was provided
            if not len1 == len2 == len3 == len4:
                raise ValueError(
                    "Provided conditional argument lists are different in length!"
                )
            cond_result = None
            for op, field, value, value_when_null in zip(
                conditional_operators,
                conditional_fields,
                conditional_values,
                conditional_field_values_when_null,
            ):
                conditional_operator = operator_symbol_function_map[op]
                res = evaluate_condition(
                    field_dict, field, value, conditional_operator, value_when_null
                )
                if cond_result is None:
                    cond_result = res
                else:
                    cond_result = operator_symbol_function_map[
                        conditional_boolean_function
                    ](cond_result, res)
            if cond_result:
                anonymization_operation = self.__getattribute__(
                    conditional_args_dict["function"]
                )
                function_args = conditional_args_dict.get("function_args", [])
                parts = conditional_args_dict["target_field"].split(".")
                root = field_dict
                last_key = parts[-1]
                if len(parts) > 1:
                    for key in parts[:-1]:
                        root = root[key]
                if isinstance(root[last_key], list):
                    root[last_key] = [
                        anonymization_operation(v, *function_args)
                        for v in root[last_key]
                    ]
                else:
                    root[last_key] = anonymization_operation(
                        root[last_key], *function_args
                    )

        operator_symbol_function_map = {
            "<": operator.lt,
            "<=": operator.le,
            "==": operator.eq,
            "=": operator.eq,
            "!=": operator.ne,
            ">": operator.gt,
            ">=": operator.ge,
            "and": operator.and_,
            "or": operator.or_,
            "in": contains_wrapper,
            "not in": not_contains,
        }

        if type(conditional_args) == list:
            for cond_arg in conditional_args:
                execute_conditional_operator(cond_arg)
        else:
            execute_conditional_operator(conditional_args)

        return field_dict

    def split_anonymize_and_join(self, field_value: str, anonymize_args: dict):
        """
        Apply anonymization operation to each separated element inside a string

        :param field_value: input string containing the elements to perform operation on
        :param anonymize_args: dictionary containing following arguments:
            - separator: character/string used to separate elements inside input string
            - function: anonymization operation to perform on the individual elements
            - function_args (optional): additional arguments for the operation to perform (default is empty list)
            - cast_element_to (optional): type to cast element to before performing operation (default is "str")
        :return: string with replaced separated values (separator type remains the same as in input string,
                 leading and trailing whitespaces in substrings are being removed)
        """
        if field_value is None:
            return None

        list_of_elements = []
        operation = self.__getattribute__(anonymize_args["function"])
        function_args = anonymize_args.get("function_args", [])
        cast_to = getattr(builtins, anonymize_args.get("cast_element_to", "str"))
        sep = anonymize_args["separator"]
        for element in field_value.split(sep):
            element = element.strip()
            try:
                element = cast_to(element)
            except ValueError:
                element = None
            # If result is None set it to "null", to ensure we don't mix null and None in our data
            # e.g.: json.dumps({"a": None})='{"a": null}' but json.dumps({"a": "None"}='{"a": "None"}'
            result = operation(element, *function_args)
            if result is None:
                list_of_elements.append("null")
            else:
                list_of_elements.append(str(result))
        return sep.join(list_of_elements)

    def apply_function_on_field_in_json_string(
        self, field_value: str, anonymize_args: dict
    ):
        """
        Apply the anonymization operation to a field inside a json object represented as a string

        :param field_value: string containing the json object with the field to apply operation on
        :param anonymize_args: dictionary containing following arguments:
            - target_field: field inside the json object to apply operation on
            - function: anonymization operation to perform on the target_field value
            - function_args (optional): additional arguments for the operation to perform (default is empty list)
            - cast_element_to (optional): type to cast value to before performing operation (default is "str")
        :return: string containing the updated json object
        """
        if field_value is None:
            return None

        operation = self.__getattribute__(anonymize_args["function"])
        cast_to = getattr(builtins, anonymize_args.get("cast_element_to", "str"))
        function_args = anonymize_args.get("function_args", [])
        field_value = json.loads(field_value)
        target_field = anonymize_args["target_field"]
        if target_field in field_value.keys():
            try:
                value = cast_to(field_value[target_field])
            except ValueError:
                value = None
            field_value[target_field] = operation(value, *function_args)

        return json.dumps(field_value)

    def serialize_to_json_string(self, field_value):
        """
        Serialize the field :field_value to JSON string.
        IMPORTANT: use it just if you are super sure that the field does not contain other PII.
        :return: json string for :field_value
        """
        return json.dumps(field_value)
