import unittest
from anonymizer import AnonymizationOperators


class AnonymizationOperatorsTestCase(unittest.TestCase):
    def test_round_ip(self):
        self.assertEqual(
            "192.168.0.0", AnonymizationOperators(None).round_ip("192.168.1.1")
        )

    def test_round_ip_null_value(self):
        self.assertEqual(None, AnonymizationOperators(None).round_ip(None))

    def test_put_to_null(self):
        self.assertEqual(None, AnonymizationOperators(None).put_to_null("192.168.1.1"))

    def test_round_float_to_integer(self):
        self.assertEqual(
            193, AnonymizationOperators(None).round_float_to_integer(192.8)
        )

    def test_round_float_to_integer_null_value(self):
        self.assertEqual(
            None, AnonymizationOperators(None).round_float_to_integer(None)
        )

    def test_round_float_to_integer_value_0(self):
        self.assertEqual(0, AnonymizationOperators(None).round_float_to_integer(0))

    def test_encryption(self):
        self.assertEqual(
            "KfrlmeI/MCzm5GUeRFz0ag==", AnonymizationOperators("123").encrypt("test")
        )

    def test_round_float(self):
        anonymization_operators = AnonymizationOperators(None)
        self.assertEqual(3.7, anonymization_operators.round_float(3.73, 1))
        self.assertEqual(3.74, anonymization_operators.round_float(3.738, 2))
        self.assertEqual(4.0, anonymization_operators.round_float(3.738, 0))

    def test_is_string_present(self):
        anonymization_operators = AnonymizationOperators(None)
        self.assertEqual("true", anonymization_operators.is_string_present("test"))
        self.assertEqual("false", anonymization_operators.is_string_present(""))
        self.assertEqual("false", anonymization_operators.is_string_present(None))
        self.assertEqual("true", anonymization_operators.is_string_present("null"))
        self.assertEqual("false", anonymization_operators.is_string_present(" "))
        self.assertEqual("true", anonymization_operators.is_string_present("false"))
        self.assertEqual("true", anonymization_operators.is_string_present(" a"))
        self.assertEqual("false", anonymization_operators.is_string_present(1))

    def test_is_number_present(self):
        anonymization_operators = AnonymizationOperators(None)
        self.assertEqual(0, anonymization_operators.is_number_present("test"))
        self.assertEqual(1, anonymization_operators.is_number_present(111))
        self.assertEqual(1, anonymization_operators.is_number_present(7.6))
        self.assertEqual(1, anonymization_operators.is_number_present(0))
        self.assertEqual(1, anonymization_operators.is_number_present(-1))
        self.assertEqual(0, anonymization_operators.is_number_present(None))

    def test_is_email_present_or_test(self):
        anonymization_operators = AnonymizationOperators(None)
        self.assertEqual(
            "invalid",
            anonymization_operators.is_email_present_or_test("test", ["testing.com"]),
        )
        self.assertEqual(
            "false",
            anonymization_operators.is_email_present_or_test(None, ["testing.com"]),
        )
        self.assertEqual(
            "true",
            anonymization_operators.is_email_present_or_test(
                "test@gmail.com", ["testing.com"]
            ),
        )
        self.assertEqual(
            "test",
            anonymization_operators.is_email_present_or_test(
                "a@TESTING.com", ["Testing.com"]
            ),
        )
        self.assertEqual(
            "true",
            anonymization_operators.is_email_present_or_test("a@testing.com", []),
        )

    def test_truncate_day_from_str(self):
        anonymization_operators = AnonymizationOperators(None)
        self.assertEqual(
            "0001-05-01",
            anonymization_operators.truncate_day_from_str("0001-05-09", "%Y-%m-%d"),
        )
        self.assertEqual(
            "0999-05-01",
            anonymization_operators.truncate_day_from_str("0999-05-09", "%Y-%m-%d"),
        )
        self.assertEqual(
            "1900-01-01",
            anonymization_operators.truncate_day_from_str("1900-01-01", "%Y-%m-%d"),
        )
        self.assertEqual(
            "2020-05-01",
            anonymization_operators.truncate_day_from_str("2020-05-09", "%Y-%m-%d"),
        )
        self.assertTrue(
            "invalid_pattern"
            in anonymization_operators.truncate_day_from_str("2020-05-09", "%Y-%m-%m")
        )
        self.assertEqual(
            "input_does_not_match_pattern: %Y-%m-%d",
            anonymization_operators.truncate_day_from_str("2020-05", "%Y-%m-%d"),
        )
        self.assertEqual(
            "input_does_not_match_pattern: %Y-%m-%d",
            anonymization_operators.truncate_day_from_str("aaaa-05-09", "%Y-%m-%d"),
        )
        self.assertEqual(
            "input_does_not_match_pattern: hello",
            anonymization_operators.truncate_day_from_str("2020-05-20", "hello"),
        )
        self.assertTrue(
            "invalid_pattern: missing",
            anonymization_operators.truncate_day_from_str("2020-05-20", None),
        )
        self.assertIsNone(
            anonymization_operators.truncate_day_from_str(None, "%Y-%m-%d")
        )
        self.assertIsNone(anonymization_operators.truncate_day_from_str(1, "%Y-%m-%d"))
        self.assertEqual(
            "2011-11-01T00:00:00.000000",
            anonymization_operators.truncate_day_from_str(
                "2011-11-04T00:05:23.283", "%Y-%m-%dT%H:%M:%S.%f"
            ),
        )

    def test_truncate_day_from_posixtimestamp(self):
        anonymization_operators = AnonymizationOperators(None)
        self.assertEqual(
            None, anonymization_operators.truncate_day_from_posix_timestamp(None)
        )
        self.assertEqual(
            None, anonymization_operators.truncate_day_from_posix_timestamp("12345")
        )
        self.assertEqual(
            1588291200,
            anonymization_operators.truncate_day_from_posix_timestamp(1588381200),
        )
        self.assertEqual(
            -147398400,
            anonymization_operators.truncate_day_from_posix_timestamp(-146485758),
        )

    def test_truncate_day_from_milliseconds_since_epoch(self):
        anonymization_operators = AnonymizationOperators(None)
        self.assertEqual(
            None, anonymization_operators.truncate_day_from_epoch_milliseconds(None)
        )
        self.assertEqual(
            None, anonymization_operators.truncate_day_from_epoch_milliseconds("12345")
        )
        self.assertEqual(
            1588291200000,
            anonymization_operators.truncate_day_from_epoch_milliseconds(1588381200000),
        )
        self.assertEqual(
            -147398400000,
            anonymization_operators.truncate_day_from_epoch_milliseconds(-146534400000),
        )

    def test_replace_regex_matches_with_string(self):
        anonymization_operators = AnonymizationOperators(None)
        test_string = "https://www.testing.com/ru/user/5894e20e-a7af-471e-bf3f-042cd81b8ac6/dashboard"
        guid_pattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        output = anonymization_operators.replace_regex_matches_with_string(
            test_string, guid_pattern, "anonymized"
        )
        self.assertEqual("https://www.testing.com/ru/user/anonymized/dashboard", output)
        output = anonymization_operators.replace_regex_matches_with_string(
            None, guid_pattern, "anonymized"
        )
        self.assertEqual(None, output)

    def test_conditional_anonymizer_equal_condition_met(self):
        self.assertEqual(
            {"type": "group", "id": "Zh7hpRitlY7ANahH3RDk7w=="},
            AnonymizationOperators("123").conditional_operation(
                {"type": "group", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "==",
                    "conditional_fields": "type",
                    "conditional_field_values_when_null": None,
                    "conditional_values": "group",
                },
            ),
        )

    def test_conditional_anonymizer_in_condition_met(self):
        self.assertEqual(
            {"type": "community_group", "id": "Zh7hpRitlY7ANahH3RDk7w=="},
            AnonymizationOperators("123").conditional_operation(
                {"type": "community_group", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "in",
                    "conditional_fields": "type",
                    "conditional_field_values_when_null": None,
                    "conditional_values": [["runners_group", "community_group"]],
                },
            ),
        )

    def test_conditional_anonymizer_in_condition_not_met(self):
        self.assertEqual(
            {"type": "group", "id": "1234567"},
            AnonymizationOperators("123").conditional_operation(
                {"type": "group", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "in",
                    "conditional_fields": "type",
                    "conditional_field_values_when_null": None,
                    "conditional_values": [["runners_group", "community_group"]],
                },
            ),
        )

    def test_conditional_anonymizer_not_in_condition_met(self):
        self.assertEqual(
            {"type": "group", "id": "Zh7hpRitlY7ANahH3RDk7w=="},
            AnonymizationOperators("123").conditional_operation(
                {"type": "group", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "not in",
                    "conditional_fields": "type",
                    "conditional_field_values_when_null": None,
                    "conditional_values": [["runners_group", "community_group"]],
                },
            ),
        )

    def test_conditional_anonymizer_not_in_condition_not_met(self):
        self.assertEqual(
            {"type": "community_group", "id": "1234567"},
            AnonymizationOperators("123").conditional_operation(
                {"type": "community_group", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "not in",
                    "conditional_fields": "type",
                    "conditional_field_values_when_null": None,
                    "conditional_values": [["runners_group", "community_group"]],
                },
            ),
        )

    def test_conditional_anonymizer_multiple_conditional_args(self):
        original_dict = {"type": "group", "id": "1234567", "name": "some_type"}
        expected_dict_after_anonymization = {
            "type": "group",
            "id": "Zh7hpRitlY7ANahH3RDk7w==",
            "name": None,
        }
        conditional_arg_1 = {
            "function": "encrypt",
            "target_field": "id",
            "conditional_operators": "==",
            "conditional_fields": "type",
            "conditional_field_values_when_null": None,
            "conditional_values": "group",
        }
        conditional_arg_2 = {
            "function": "put_to_null",
            "target_field": "name",
            "conditional_operators": "==",
            "conditional_fields": "type",
            "conditional_field_values_when_null": None,
            "conditional_values": "group",
        }
        self.assertEqual(
            expected_dict_after_anonymization,
            AnonymizationOperators("123").conditional_operation(
                original_dict, [conditional_arg_1, conditional_arg_2]
            ),
        )

    def test_conditional_anonymizer_equal_condition_not_met(self):
        self.assertEqual(
            {"type": "group", "id": "1234567"},
            AnonymizationOperators("123").conditional_operation(
                {"type": "group", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "==",
                    "conditional_fields": "type",
                    "conditional_field_values_when_null": None,
                    "conditional_values": "user",
                },
            ),
        )

    def test_conditional_anonymizer_different_than_condition_met(self):
        self.assertEqual(
            {"type": "user", "id": "Zh7hpRitlY7ANahH3RDk7w=="},
            AnonymizationOperators("123").conditional_operation(
                {"type": "user", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "!=",
                    "conditional_fields": "type",
                    "conditional_field_values_when_null": None,
                    "conditional_values": "some_type",
                },
            ),
        )

    def test_conditional_anonymizer_different_than_condition_not_met(self):
        self.assertEqual(
            {"type": "some_type", "id": "1234567"},
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "!=",
                    "conditional_fields": "type",
                    "conditional_field_values_when_null": None,
                    "conditional_values": "some_type",
                },
            ),
        )

    def test_conditional_anonymizer_single_equal_condition_met(self):
        self.assertEqual(
            {"type": "some_type", "id": "Zh7hpRitlY7ANahH3RDk7w=="},
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["="],
                    "conditional_fields": ["type"],
                    "conditional_field_values_when_null": None,
                    "conditional_values": ["some_type"],
                },
            ),
        )

    def test_conditional_anonymizer_combination_not_in_operator_condition_met(self):
        self.assertEqual(
            {
                "type": "community_group",
                "id": "Zh7hpRitlY7ANahH3RDk7w==",
                "next_layer": {"count": 2},
            },
            AnonymizationOperators("123").conditional_operation(
                {
                    "type": "community_group",
                    "id": "1234567",
                    "next_layer": {"count": 2},
                },
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["not in", "<"],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": [None, 0],
                    "conditional_values": [["group", "runners_group"], 3],
                    "conditional_boolean_function": "or",
                },
            ),
        )

    def test_conditional_anonymizer_combination_not_in_operator_condition_not_met(self):
        self.assertEqual(
            {"type": "community_group", "id": "1234567", "next_layer": {"count": 2}},
            AnonymizationOperators("123").conditional_operation(
                {
                    "type": "community_group",
                    "id": "1234567",
                    "next_layer": {"count": 2},
                },
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["not in", "<"],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": [None, 0],
                    "conditional_values": [["community_group", "runners_group"], 2],
                    "conditional_boolean_function": "or",
                },
            ),
        )

    def test_conditional_anonymizer_combination_condition_met(self):
        self.assertEqual(
            {
                "type": "some_type",
                "id": "Zh7hpRitlY7ANahH3RDk7w==",
                "next_layer": {"count": 2},
            },
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567", "next_layer": {"count": 2}},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["==", "<"],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": [None, 0],
                    "conditional_values": ["some_type", 3],
                    "conditional_boolean_function": "and",
                },
            ),
        )

    def test_conditional_anonymizer_combination_compare_with_null_int_met(self):
        self.assertEqual(
            {
                "type": "some_type",
                "id": "Zh7hpRitlY7ANahH3RDk7w==",
                "next_layer": {"count": None},
            },
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567", "next_layer": {"count": None}},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["==", "<"],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": [None, 0],
                    "conditional_values": ["some_type", 3],
                    "conditional_boolean_function": "and",
                },
            ),
        )

    def test_conditional_anonymizer_combination_compare_with_null_int_not_met(self):
        self.assertEqual(
            {"type": "some_type", "id": "1234567", "next_layer": {"count": None}},
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567", "next_layer": {"count": None}},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["==", "<"],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": [None, 5],
                    "conditional_values": ["some_type", 3],
                    "conditional_boolean_function": "and",
                },
            ),
        )

    def test_conditional_anonymizer_combination_compare_with_null_str_met(self):
        self.assertEqual(
            {
                "type": None,
                "id": "Zh7hpRitlY7ANahH3RDk7w==",
                "next_layer": {"count": 1},
            },
            AnonymizationOperators("123").conditional_operation(
                {"type": None, "id": "1234567", "next_layer": {"count": 1}},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["==", "<"],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": [None, 0],
                    "conditional_values": [None, 3],
                    "conditional_boolean_function": "and",
                },
            ),
        )

    @unittest.expectedFailure
    def test_conditional_anonymizer_combination_fail_when_missing_args1(self):
        self.assertEqual(
            {
                "type": None,
                "id": "Zh7hpRitlY7ANahH3RDk7w==",
                "next_layer": {"count": 1},
            },
            AnonymizationOperators("123").conditional_operation(
                {"type": None, "id": "1234567", "next_layer": {"count": 1}},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["==", "<"],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": None,
                    "conditional_values": [None, 3],
                    "conditional_boolean_function": "and",
                },
            ),
        )

    @unittest.expectedFailure
    def test_conditional_anonymizer_combination_fail_when_missing_args2(self):
        self.assertEqual(
            {
                "type": None,
                "id": "Zh7hpRitlY7ANahH3RDk7w==",
                "next_layer": {"count": 1},
            },
            AnonymizationOperators("123").conditional_operation(
                {"type": None, "id": "1234567", "next_layer": {"count": 1}},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["=="],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": [None, 0],
                    "conditional_values": [None, 3],
                    "conditional_boolean_function": "and",
                },
            ),
        )

    def test_conditional_anonymizer_combination_condition_not_met(self):
        self.assertEqual(
            {"type": "some_type", "id": "1234567", "next_layer": {"count": 2}},
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567", "next_layer": {"count": 2}},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": ["==", ">"],
                    "conditional_fields": ["type", "next_layer.count"],
                    "conditional_field_values_when_null": [None, 0],
                    "conditional_values": ["some_type", 3],
                    "conditional_boolean_function": "and",
                },
            ),
        )

    def test_conditional_anonymizer_equal_to_true_lower_case_condition_met(self):
        self.assertEqual(
            {"type": "some_type", "id": "Zh7hpRitlY7ANahH3RDk7w==", "valid": True},
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567", "valid": True},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "==",
                    "conditional_fields": "valid",
                    "conditional_field_values_when_null": None,
                    "conditional_values": True,
                },
            ),
        )

    def test_conditional_anonymizer_equal_to_true_upper_case_condition_met(self):
        self.assertEqual(
            {"type": "some_type", "id": "Zh7hpRitlY7ANahH3RDk7w==", "valid": True},
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567", "valid": True},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "==",
                    "conditional_fields": "valid",
                    "conditional_field_values_when_null": None,
                    "conditional_values": True,
                },
            ),
        )

    def test_conditional_anonymizer_equal_to_null_condition_met(self):
        self.assertEqual(
            {"type": "some_type", "id": "Zh7hpRitlY7ANahH3RDk7w==", "valid": None},
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567", "valid": None},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_operators": "==",
                    "conditional_fields": "valid",
                    "conditional_field_values_when_null": None,
                    "conditional_values": None,
                },
            ),
        )

    def test_conditional_anonymizer_equal_to_null_condition_not_met(self):
        self.assertEqual(
            {"type": "some_type", "id": "1234567", "valid": "yes"},
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "id": "1234567", "valid": "yes"},
                {
                    "function": "encrypt",
                    "target_field": "id",
                    "conditional_fields": "valid",
                    "conditional_values": None,
                    "conditional_field_values_when_null": None,
                    "conditional_operators": "==",
                },
            ),
        )

    def test_conditional_anonymizer_equal_to_null_condition_met_array(self):
        self.assertEqual(
            {
                "type": "some_type",
                "ids": ["Zh7hpRitlY7ANahH3RDk7w==", "Zh7hpRitlY7ANahH3RDk7w=="],
                "valid": "yes",
            },
            AnonymizationOperators("123").conditional_operation(
                {"type": "some_type", "ids": ["1234567", "1234567"], "valid": "yes"},
                {
                    "function": "encrypt",
                    "target_field": "ids",
                    "conditional_fields": "valid",
                    "conditional_field_values_when_null": None,
                    "conditional_values": "yes",
                    "conditional_operators": "==",
                },
            ),
        )

    def test_serialize_to_json_string(self):
        self.assertEqual(
            '{"type": "some_type", "ids": ["1234567", "1234567"]}',
            AnonymizationOperators("123").serialize_to_json_string(
                {"type": "some_type", "ids": ["1234567", "1234567"]}
            ),
        )
        self.assertEqual(
            '"some_type"',
            AnonymizationOperators("123").serialize_to_json_string("some_type"),
        )
        self.assertEqual("1", AnonymizationOperators("123").serialize_to_json_string(1))

    def test_convert_to_field_length(self):
        self.assertEqual(
            5, AnonymizationOperators("123").convert_to_field_length("hello")
        )
        self.assertEqual(0, AnonymizationOperators("123").convert_to_field_length(""))
        self.assertEqual(0, AnonymizationOperators("123").convert_to_field_length(None))
        self.assertEqual(
            3, AnonymizationOperators("123").convert_to_field_length([1, 2, 3])
        )


if __name__ == "__main__":
    unittest.main()
