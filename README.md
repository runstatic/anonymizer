# Anonymization library

This is a library to perform anonymization operations on JSON data.

## ⚠️ No longer maintained ⚠️

This library was developed by the Data Engineering team @ Runtastic in Austria. We decided to open source it as anonymization is relevant to any project dealing with data privacy regulations, like GDPR.

## How to use

### Anonymizer

Anonymizer constructor takes:
- `json_schema` (or `json_schema_str`)
-  `encryption_secret`: secret to be used in case of encryption operations (default `None`)

Once initialized the anonymizer object you can call the functions `anonymize_json_str` or `anonymize_json`
in order to anonymize a JSON based on the rule specified in the schema.


Example: 
```python
# Initialize the Anonymizer object passing JSON schema as string
anonymizer = Anonymizer(json_schema=schema_str)

# Anonymize JSON passing it as a string
anonymized_json = anonymizer.anonymize_json_str(test_json_str)

# Anonymize JSON passing it as a parsed dictionary
anonymized_json = anonymizer.anonymize_json(test_json_dict)
```

### JSON Schema rules

In order to anonymize a field you have to specify in the schema two extra fields:

- `x-anonymize-operation`: string representing the name of the anonymization operation
- `x-anonymize-args`: list of args for the anonymization operation. If the operation does not
take any arguments, this field can be omitted.

#### Where?

You have to add the fields `x-anonymize-operation` and `x-anonymize-args` in the schema of
the field you want to anonymize (for example, alongside its `type` definition).

Consider the example below:

```json
{
    ...
    "user": {
      "type": "object",
      "properties": {
        "id": {
          "type": "number",
          "x-anonymize-operation": "round_float",
          "x-anonymize-args": [2]
        },
        "name": {
          "type": "string"
        }
      }
  ...,
}
```

You are specifying that you want to anonymize the field `user/id` applying the operation `round_float`
keeping just `2` decimal digits.

#### Operators

All the operators are placed in the class `anonymizer.AnonymizeOperators`.
  
The following operators are available:
- `round_ip(field_value)`
    Round IP address putting the last two numbers to 0.
- `put_to_null(field_value)`
    Return None regardless the input value.
- `round_float_to_integer(field_value)`
    Round the input float to the closest integer.
- `round_float(field_value, ndigits)`
    Round float to ndigits decimal digits.
- `encrypt(field_value)`
    Encrypt the field using the encryption secret
- `is_string_present(field_value)`
    Return "false" if :field_value is empty, white-spaces, null or not a String; "true" otherwise.
- `is_number_present(field_value)`
    Return 0 if :field_value is null or not a number, 1 otherwise.
- `is_email_present_or_test(field_value, test_domains)`
    Return a string representing the existence of the email (true, false, invalid, test)
- `truncate_day_from_str(field_value, pattern)`
    Return the given date with its day set to first of the month and the time part zeroed.
- `truncate_day_from_posix_timestamp(field_value)`
    Return the given :posix_timestamp with its day set to first of the month and the time part zeroed.
- `truncate_day_from_epoch_milliseconds(field_value)`
    Return the given :milliseconds_since_epoch with its day set to first of the month and the time part zeroed.
- `replace_regex_matches_with_string(field_value, pattern, repl)`
    Return the string obtained by replacing the occurrences of the regex :pattern in :field_value by the replacement :repl.
- `conditional_operation(field_dict, conditional_args)`
    Return the dictionary with replaced field value if: condition is met, unchanged dictionary otherwise.
- `split_anonymize_and_join(field_value, anonymize_args)`
    Return the string with replaced separated values.
    
    Example 1: Round all elements inside values string to 2 decimal places. Individual substrings inside the values 
    string need to be converted to float in order to perform the `round_float` operation.
    
    Schema:
    ```json
    {
    ...
        "values": {
            "type": [
                "string",
                "null"
            ],
            "x-anonymize-operation": "split_anonymize_and_join",
            "x-anonymize-args": [{
                        "separator": ",",
                        "function": "round_float",
                        "function_args": [2],
                        "cast_element_to": "float"
            }]
        }
    ...
    }
    ```
    Input:
    ```json
    {
    ...
      "values": "3.21231, 4.23, 5.6372",
    ...
    }
    ```
    Output:
    ```json
    {
    ...
      "values": "3.21,4.23,5.64",
    ...
    }
    ```
  
    Example 2: Encrypt all elements inside values string (separator=";"). The encrypt operation does not 
    require any additional arguments, so the `function_args` field can be removed or set to []. As the encrypt operation 
    is applied on strings, no type casting is required. Therefore, the `cast_element_to` field can also be removed or 
    set to `"str"`.
    
    Schema:
    ```json
    {
    ...
        "values": {
            "type": [
                "string",
                "null"
            ],
            "x-anonymize-operation": "split_anonymize_and_join",
            "x-anonymize-args": [{
                        "separator": ";",
                        "function": "encrypt"
            }]
        }
    ...
    }
    ```
    Input:
    ```json
    {
    ...
      "values": "1234567; 2345678; 3456789",
    ...
    }
    ```
    Output:
    ```json
    {
    ...
      "values": "Zh7hpRitlY7ANahH3RDk7w==;dv4JkGA296U9MsDSc8FEFg==;HfpGShe3O0Q2wJRAVrz0XQ==",
    ...
    }
    ```
- `apply_function_on_field_in_json_string(field_value, anonymize_args)`
    Return a string representation of a json object after applying a function to one of its fields. In case the
    operation to perform on the field requires a different data type than string (e.g. round_float) also add a
    "cast_element_to" field to the schema (just like in example 1 of the split_anonymize_and_join operator).
    
    Example: Remove the id from the "content_type". Be aware that the value of the "values" field is 
    actually a string containing a json object.
    
    Schema:
    ```json
    {
    ...
        "values": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "apply_function_on_field_in_json_string",
                    "x-anonymize-args": [{
                                "target_field": "content_type",
                                "function": "replace_regex_matches_with_string",
                                "function_args": ["group.*", "group"]
                    }]
                }
    ...
    }
    ```
    Input:
    ```json
    {
    ...
      "event_id": "user",
      "values": "{\"time_frame\": \"this_month\", \"content_type\": \"group_75127213-5840-41d0-b96b-e3f6c63c0ec1\"}"
    ...
    }
    ```
    Output:
    ```json
    {
    ...
      "event_id": "user",
      "values": "{\"time_frame\": \"this_month\", \"content_type\": \"group\"}"
    ...
    }
    ```
- `serialize_to_json_string(field_value)` Serialize the field :field_value to JSON string. IMPORTANT: Don't use it if field_value contains PII. 
- `convert_to_field_length(field_value)` Return the length of :field_value (string/array).