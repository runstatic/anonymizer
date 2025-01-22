import unittest

from anonymizer import Anonymizer, InitializationException
import json


class AnonymizerTestCase(unittest.TestCase):
    def test_anonymizer_instantiation_fail(self):
        self.assertRaises(InitializationException, Anonymizer)

    def test_single_chunk_path_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string",
              "x-anonymize-operation": "put_to_null",
              "x-anonymize-args": []
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": null,
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_single_missing_chunk_path_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string",
              "x-anonymize-operation": "put_to_null",
              "x-anonymize-args": []
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_twolevel_chunk_path_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer",
                  "x-anonymize-operation": "put_to_null",
                  "x-anonymize-args": []
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": {
                "id": null,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_missing_twolevel_chunk_path_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer",
                  "x-anonymize-operation": "put_to_null",
                  "x-anonymize-args": []
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": {
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_null_subtree_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer",
                  "x-anonymize-operation": "is_number_present",
                  "x-anonymize-args": []
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": null,
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": null,
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_complex_array_chunk_path_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer",
                      "x-anonymize-operation": "put_to_null",
                      "x-anonymize-args": []
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"id": null, "lat": 100.222},
                {"id": null, "lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_missing_complex_array_chunk_path_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer",
                      "x-anonymize-operation": "put_to_null",
                      "x-anonymize-args": []
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"lat": 100.222},
                {"lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"lat": 100.222},
                {"lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_simple_array_chunk_path_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "double",
                  "x-anonymize-operation": "round_float_to_integer",
                  "x-anonymize-args": []
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                33.3,
                33.8,
                11.4
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                33,
                34,
                11
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_empty_array_chunk_path_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "integer"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "double",
                  "x-anonymize-operation": "round_float_to_integer",
                  "x-anonymize-args": []
              }
            }
          },
          "anonymize": [
            {"path": "sessions/[*]" , "operation": "round_float_to_integer"}
          ]
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_args_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
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
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331.788,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": {
                "id": 331.79,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_args_missing_param_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "number",
                  "x-anonymize-operation": "round_float"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331.788,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        anonymizer = Anonymizer(json_schema_str=schema_str)
        self.assertRaises(TypeError, anonymizer.anonymize_json_str, test_json_str)

    def test_args_missing_args_field_function_application(self):

        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": "object",
              "properties": {
                "id": {
                  "type": "number",
                  "x-anonymize-operation": "round_float"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331.788,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        anonymizer = Anonymizer(json_schema_str=schema_str)
        self.assertRaises(Exception, anonymizer.anonymize_json_str, test_json_str)

    def test_type_is_array(self):
        """
        the type field can be an array of all options, not just a string. This case is tested here.
        """
        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "event_id": {
              "type": "string"
            },
            "user": {
              "type": ["null", "object"],
              "properties": {
                "id": {
                  "type": "integer",
              "x-anonymize-operation": "put_to_null"
                },
                "name": {
                  "type": "string"
                }
              }
            },
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              }
            }
          }
        }
        """

        test_json_str = """
            {
              "event_id": "user",
              "user": {
                "id": 331,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "user": {
                "id": null,
                "name": "Markus"
              },
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_anonymization_equal_condition_met(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "user": {
                    "type": [
                        "object",
                        "null"
                    ],
                    "additionalProperties": false,
                    "properties": {
                        "data": {
                            "type": [
                                "object",
                                "null"
                            ],
                            "x-anonymize-operation": "conditional_operation",
                            "x-anonymize-args": [{
                                "function": "encrypt",
                                "target_field": "id",
                                "conditional_fields": "type",
                                "conditional_field_values_when_null": null,
                                "conditional_values": "user",
                                "conditional_operators": "=="  
                            }],
                            "additionalProperties": false,
                            "properties": {
                                "id": {
                                    "type": [
                                        "string",
                                        "null"
                                    ]
                                },
                                "type": {
                                    "type": [
                                        "string",
                                        "null"
                                    ]
                                }
                            }
                        }
                    }
                }
              }
            }
        """
        test_json_str = """
            {
              "user": {
                  "data": {
                    "type": "user",
                    "id": "1234567"
                  }
                }
            }
        """
        expected_json = json.loads(
            """
            {
              "user": {
                  "data": {
                    "type": "user",
                    "id": "Zh7hpRitlY7ANahH3RDk7w=="
                  }
                }
            }
        """
        )
        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_anonymization_different_than_condition_met(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "user": {
                    "type": [
                        "object",
                        "null"
                    ],
                    "additionalProperties": false,
                    "properties": {
                        "data": {
                            "type": [
                                "object",
                                "null"
                            ],
                            "x-anonymize-operation": "conditional_operation",
                            "x-anonymize-args": [{
                                "function": "encrypt",
                                "target_field": "id",
                                "conditional_fields": "type",
                                "conditional_field_values_when_null": null,
                                "conditional_values": "special",
                                "conditional_operators": "!="  
                            }],
                            "additionalProperties": false,
                            "properties": {
                                "id": {
                                    "type": [
                                        "string",
                                        "null"
                                    ]
                                },
                                "type": {
                                    "type": [
                                        "string",
                                        "null"
                                    ]
                                }
                            }
                        }
                    }
                }
              }
            }
        """
        test_json_str = """
            {
              "user": {
                  "data": {
                    "type": "user",
                    "id": "1234567"
                  }
                }
            }
        """
        expected_json = json.loads(
            """
            {
              "user": {
                  "data": {
                    "type": "user",
                    "id": "Zh7hpRitlY7ANahH3RDk7w=="
                  }
                }
            }
        """
        )
        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_anonymization_equal_condition_not_met(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "user": {
                    "type": [
                        "object",
                        "null"
                    ],
                    "additionalProperties": false,
                    "properties": {
                        "data": {
                            "type": [
                                "object",
                                "null"
                            ],
                            "x-anonymize-operation": "conditional_operation",
                            "x-anonymize-args": [{
                                "function": "encrypt",
                                "target_field": "id",
                                "conditional_fields": "type",
                                "conditional_field_values_when_null": null,
                                "conditional_values": "user",
                                "conditional_operators": "="  
                            }],
                            "additionalProperties": false,
                            "properties": {
                                "id": {
                                    "type": [
                                        "string",
                                        "null"
                                    ]
                                },
                                "type": {
                                    "type": [
                                        "string",
                                        "null"
                                    ]
                                }
                            }
                        }
                    }
                }
              }
            }
        """
        test_json_str = """
            {
              "user": {
                  "data": {
                    "type": "group",
                    "id": "1234567"
                  }
                }
            }
        """
        expected_json = json.loads(
            """
            {
              "user": {
                  "data": {
                    "type": "group",
                    "id": "1234567"
                  }
                }
            }
        """
        )
        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_anonymization_different_than_condition_not_met(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "user": {
                    "type": [
                        "object",
                        "null"
                    ],
                    "additionalProperties": false,
                    "properties": {
                        "data": {
                            "type": [
                                "object",
                                "null"
                            ],
                            "x-anonymize-operation": "conditional_operation",
                            "x-anonymize-args": [{
                                "function": "encrypt",
                                "target_field": "id",
                                "conditional_fields": "type",
                                "conditional_field_values_when_null": null,
                                "conditional_values": "special",
                                "conditional_operators": "!="  
                            }],
                            "additionalProperties": false,
                            "properties": {
                                "id": {
                                    "type": [
                                        "string",
                                        "null"
                                    ]
                                },
                                "type": {
                                    "type": [
                                        "string",
                                        "null"
                                    ]
                                }
                            }
                        }
                    }
                }
              }
            }
        """
        test_json_str = """
            {
              "user": {
                  "data": {
                    "type": "special",
                    "id": "1234567"
                  }
                }
            }
        """
        expected_json = json.loads(
            """
            {
              "user": {
                  "data": {
                    "type": "special",
                    "id": "1234567"
                  }
                }
            }
        """
        )
        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    # region HUGE tests

    def test_conditional_operation_for_group_message_condition_met(self):
        schema_str = """
        {
            "type":[
                "object"
            ],
            "additionalProperties":false,
            "properties":{
                "included":{
                    "type":[
                        "array",
                        "null"
                    ],
                    "items":{
                        "type":[
                            "object",
                            "null"
                        ],
                        "x-anonymize-operation":"conditional_operation",
                        "x-anonymize-args": [{
                            "function": "put_to_null",
                            "target_field": "attributes.name",
                            "conditional_fields": ["type", "attributes.member_count"],
                            "conditional_values": ["random_group", 5000],
                            "conditional_field_values_when_null": [null, 0],
                            "conditional_operators": ["!=", "<"],
                            "conditional_boolean_function": "or"
                        }],
                        "additionalProperties":false,
                        "properties":{
                            "attributes":{
                                "type":[
                                    "object",
                                    "null"
                                ],
                                "additionalProperties":false,
                                "properties":{
                                    "member_count":{
                                        "type":[
                                            "integer",
                                            "null"
                                        ]
                                    },
                                    "name":{
                                        "type":[
                                            "string",
                                            "null"
                                        ]
                                    }
                                }
                            },
                            "type":{
                                "type":[
                                    "string",
                                    "null"
                                ]
                            }
                        }
                    }
                }
            }
        }
        """
        test_json_str = """
        {
            "included":[
                {
                    "type":"random_group",
                    "attributes":{
                        "name":"Group Singapore",
                        "member_count":4202
                    }
                }
            ]
        }
        """
        expected_json = json.loads(
            """
        {
            "included":[
                {
                    "attributes":{
                        "member_count":4202,
                        "name":null
                    },
                    "type":"random_group"
                }
            ]
        }
        """
        )
        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.maxDiff = None
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_operation_for_group_message_condition_not_met(self):
        schema_str = """
        {
            "type":[
                "object"
            ],
            "additionalProperties":false,
            "properties":{
                "included":{
                    "type":[
                        "array",
                        "null"
                    ],
                    "items":{
                        "type":[
                            "object",
                            "null"
                        ],
                        "x-anonymize-operation":"conditional_operation",
                        "x-anonymize-args": [{
                            "function": "put_to_null",
                            "target_field": "attributes.name",
                            "conditional_fields": ["type", "attributes.member_count"],
                            "conditional_values": ["random_group", 100],
                            "conditional_field_values_when_null": [null, 0],
                            "conditional_operators": ["!=", "<"],
                            "conditional_boolean_function": "or"
                        }],
                        "additionalProperties":false,
                        "properties":{
                            "attributes":{
                                "type":[
                                    "object",
                                    "null"
                                ],
                                "additionalProperties":false,
                                "properties":{
                                    "member_count":{
                                        "type":[
                                            "integer",
                                            "null"
                                        ]
                                    },
                                    "name":{
                                        "type":[
                                            "string",
                                            "null"
                                        ]
                                    }
                                }
                            },
                            "type":{
                                "type":[
                                    "string",
                                    "null"
                                ]
                            }
                        }
                    }
                }
            }
        }
        """

        test_json_str = """
        {
            "included":[
                {
                    "type":"random_group",
                    "attributes":{
                        "name":"Group Singapore",
                        "member_count":4202
                    }
                }
            ]
        }
        """

        expected_json = json.loads(
            """
        {
            "included":[
                {
                    "attributes":{
                        "member_count":4202,
                        "name":"Group Singapore"
                    },
                    "type":"random_group"
                }
            ]
        }"""
        )
        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.maxDiff = None
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_operation_for_group_message_condition_not_met_with_null(self):
        schema_str = """
        {
            "type":[
                "object"
            ],
            "additionalProperties":false,
            "properties":{
                "included":{
                    "type":[
                        "array",
                        "null"
                    ],
                    "items":{
                        "type":[
                            "object",
                            "null"
                        ],
                        "x-anonymize-operation":"conditional_operation",
                        "x-anonymize-args": [{
                            "function": "put_to_null",
                            "target_field": "attributes.name",
                            "conditional_fields": ["type", "attributes.member_count"],
                            "conditional_field_values_when_null": [null, 0],
                            "conditional_values": ["random_group", 100],
                            "conditional_operators": ["!=", ">"],
                            "conditional_boolean_function": "or"
                        }],
                        "additionalProperties":false,
                        "properties":{
                            "attributes":{
                                "type":[
                                    "object",
                                    "null"
                                ],
                                "additionalProperties":false,
                                "properties":{
                                    "member_count":{
                                        "type":[
                                            "integer",
                                            "null"
                                        ]
                                    },
                                    "name":{
                                        "type":[
                                            "string",
                                            "null"
                                        ]
                                    }
                                }
                            },
                            "type":{
                                "type":[
                                    "string",
                                    "null"
                                ]
                            }
                        }
                    }
                }
            }
        }
        """

        test_json_str = """
        {
            "included":[
                {
                    "type":"random_group",
                    "attributes":{
                        "name":"Group Singapore",
                        "member_count":null
                    }
                }
            ]
        }
        """

        expected_json = json.loads(
            """
        {
            "included":[
                {
                    "attributes":{
                        "member_count":null,
                        "name":"Group Singapore"
                    },
                    "type":"random_group"
                }
            ]
        }"""
        )
        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.maxDiff = None
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_operation_for_group_message_condition_not_met_with_null(self):
        schema_str = """
        {
            "type":[
                "object"
            ],
            "additionalProperties":false,
            "properties":{
                "included":{
                    "type":[
                        "array",
                        "null"
                    ],
                    "items":{
                        "type":[
                            "object",
                            "null"
                        ],
                        "x-anonymize-operation":"conditional_operation",
                        "x-anonymize-args": [{
                            "function": "put_to_null",
                            "target_field": "attributes.name",
                            "conditional_fields": ["type", "attributes.member_count"],
                            "conditional_field_values_when_null": [null, 200],
                            "conditional_values": ["random_group", 100],
                            "conditional_operators": ["!=", ">"],
                            "conditional_boolean_function": "or"
                        }],
                        "additionalProperties":false,
                        "properties":{
                            "attributes":{
                                "type":[
                                    "object",
                                    "null"
                                ],
                                "additionalProperties":false,
                                "properties":{
                                    "member_count":{
                                        "type":[
                                            "integer",
                                            "null"
                                        ]
                                    },
                                    "name":{
                                        "type":[
                                            "string",
                                            "null"
                                        ]
                                    }
                                }
                            },
                            "type":{
                                "type":[
                                    "string",
                                    "null"
                                ]
                            }
                        }
                    }
                }
            }
        }
        """

        test_json_str = """
        {
            "included":[
                {
                    "type":"random_group",
                    "attributes":{
                        "name":"Group Singapore",
                        "member_count":null
                    }
                }
            ]
        }
        """

        expected_json = json.loads(
            """
        {
            "included":[
                {
                    "attributes":{
                        "member_count":null,
                        "name":null
                    },
                    "type":"random_group"
                }
            ]
        }"""
        )
        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.maxDiff = None
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_operation_list_for_workout_message_condition_met(self):
        schema_str = """
        {
            "$schema":"http://json-schema.org/draft-07/schema#",
            "type":[
                "object",
                "null"
            ],
            "properties":{
                "included":{
                    "type":[
                        "array",
                        "null"
                    ],
                    "items":{
                        "type":[
                            "object",
                            "null"
                        ],
                        "x-anonymize-operation":"conditional_operation",
                        "x-anonymize-args":[
                            [
                                {
                                    "function":"put_to_null",
                                    "target_field":"attributes.description",
                                    "conditional_fields":"relationships.owner.data.type",
                                    "conditional_field_values_when_null":null,
                                    "conditional_values":"content_provider",
                                    "conditional_operators":"!="
                                },
                                {
                                    "function":"put_to_null",
                                    "target_field":"attributes.short_description",
                                    "conditional_fields":"relationships.owner.data.type",
                                    "conditional_field_values_when_null":null,
                                    "conditional_values":"content_provider",
                                    "conditional_operators":"!="
                                },
                                {
                                    "function":"put_to_null",
                                    "target_field":"attributes.name",
                                    "conditional_fields":"relationships.owner.data.type",
                                    "conditional_field_values_when_null":null,
                                    "conditional_values":"content_provider",
                                    "conditional_operators":"!="
                                }
                            ]
                        ],
                        "properties":{
                            "relationships":{
                                "type":[
                                    "object",
                                    "null"
                                ],
                                "properties":{
                                    "owner":{
                                        "type":[
                                            "object",
                                            "null"
                                        ],
                                        "properties":{
                                            "data":{
                                                "type":[
                                                    "object",
                                                    "null"
                                                ],
                                                "x-anonymize-operation":"conditional_operation",
                                                "x-anonymize-args":[
                                                    {
                                                        "function":"encrypt",
                                                        "target_field":"id",
                                                        "conditional_fields":"type",
                                                        "conditional_field_values_when_null":null,
                                                        "conditional_values":"content_provider",
                                                        "conditional_operators":"!="
                                                    }
                                                ],
                                                "properties":{
                                                    "id":{
                                                        "type":[
                                                            "string",
                                                            "null"
                                                        ]
                                                    },
                                                    "type":{
                                                        "type":[
                                                            "string",
                                                            "null"
                                                        ]
                                                    }
                                                },
                                                "additionalProperties":false
                                            }
                                        },
                                        "additionalProperties":false
                                    }
                                },
                                "additionalProperties":false
                            },
                            "attributes":{
                                "type":[
                                    "object",
                                    "null"
                                ],
                                "properties":{
                                    "short_description":{
                                        "type":[
                                            "string",
                                            "null"
                                        ],
                                        "x-dev-note":"Put to null in case of user owner. See included.items for the anonymization rule definition."
                                    },
                                    "description":{
                                        "type":[
                                            "string",
                                            "null"
                                        ],
                                        "x-dev-note":"Put to null in case of user owner. See included.items for the anonymization rule definition."
                                    },
                                    "name":{
                                        "type":[
                                            "string",
                                            "null"
                                        ],
                                        "x-dev-note":"Put to null in case of user owner. See included.items for the anonymization rule definition."
                                    }
                                },
                                "additionalProperties":false
                            },
                            "id":{
                                "type":[
                                    "string",
                                    "null"
                                ],
                                "x-anonymize-operation":"encrypt"
                            },
                            "type":{
                                "type":[
                                    "string",
                                    "null"
                                ]
                            }
                        },
                        "additionalProperties":false
                    }
                }
            },
            "additionalProperties":false
        }
        """

        test_json_str = """
        {
            "included":[
                {
                    "id":"4V0pehrJ1pgxK9LFRC7WOk",
                    "type":"workout",
                    "attributes":{
                        "name":"Get Pumped",
                        "short_description":"FULL BODY HIGH INTENSITY WORKOUT WITH BETTINA",
                        "description":"Random Description for a workout"
                    },
                    "relationships":{
                        "owner":{
                            "data":{
                                "type":"not_content_provider",
                                "id":"some_owner"
                            }
                        }
                    }
                }
            ]
        }
        """

        expected_json = json.loads(
            """
        {
            "included":[
                {
                    "id":"YXmNem7ZWSDqvK5+4rAXvcgBENbwxZtj5RMFDqdVmi4=",
                    "type":"workout",
                    "attributes":{
                        "name":null,
                        "short_description":null,
                        "description":null
                    },
                    "relationships":{
                        "owner":{
                            "data":{
                                "type":"not_content_provider",
                                "id":"SWscIyJxuH6MlsBcFwMWRA=="
                            }
                        }
                    }
                }
            ]
        }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.maxDiff = None
        self.assertEqual(expected_json, anonymized_json)

    # endregion

    def test_split_anonymize_and_join_encrypt(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "ui_results": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "split_anonymize_and_join",
                    "x-anonymize-args": [{
                                "separator": ",",
                                "function": "encrypt"
                    }]
                }
              }
            }
        """

        test_json_str = """
                    {
                      "event_id": "user",
                      "ui_results": "1234567, 2345678, 3456789"
                    }
                """

        expected_json = json.loads(
            """
        {
          "event_id": "user",
          "ui_results": "Zh7hpRitlY7ANahH3RDk7w==,dv4JkGA296U9MsDSc8FEFg==,HfpGShe3O0Q2wJRAVrz0XQ=="
        }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_split_anonymize_and_join_round_float(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
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
              }
            }
        """

        test_json_str = """
                    {
                      "event_id": "user",
                      "values": "3.21231, 4.23, 5.6372, 3"
                    }
                """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "3.21,4.23,5.64,3.0"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_split_anonymize_and_join_is_number_present(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "values": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "split_anonymize_and_join",
                    "x-anonymize-args": [{
                                "separator": ",",
                                "function": "is_number_present",
                                "cast_element_to": "float"
                    }]
                }
              }
            }
        """

        test_json_str = """
                    {
                      "event_id": "user",
                      "values": "3.21231, 2, not_a_number, -1"
                    }
                """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "1,1,0,1"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_split_anonymize_and_join_put_to_null(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "values": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "split_anonymize_and_join",
                    "x-anonymize-args": [{
                                "separator": ",",
                                "function": "put_to_null"
                    }]
                }
              }
            }
        """

        test_json_str = """
                    {
                      "event_id": "user",
                      "values": "3.21231, 2, not_a_number, -1"
                    }
                """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "null,null,null,null"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_split_anonymize_and_join_round_ip_semicolon(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "values": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "split_anonymize_and_join",
                    "x-anonymize-args": [{
                                "separator": ";",
                                "function": "round_ip"
                    }]
                }
              }
            }
        """

        test_json_str = """
                    {
                      "event_id": "user",
                      "values": "255.255.255.10; 255.255.200.100"
                    }
                """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "255.255.0.0;255.255.0.0"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_apply_function_on_field_in_json_string_regex(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
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
              }
            }
        """

        test_json_str = """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\":\\"this_month\\",\\"content_type\\":\\"group_75127213-5840-41d0-b96b-e3f6c63c0ec1\\"}"
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\": \\"this_month\\", \\"content_type\\": \\"group\\"}"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_apply_function_on_field_in_json_string_encrypt(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "values": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "apply_function_on_field_in_json_string",
                    "x-anonymize-args": [{
                                "target_field": "content_type",
                                "function": "encrypt"
                    }]
                }
              }
            }
        """

        test_json_str = """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\":\\"this_month\\",\\"content_type\\":\\"1234567\\"}"
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\": \\"this_month\\", \\"content_type\\": \\"Zh7hpRitlY7ANahH3RDk7w==\\"}"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_apply_function_on_field_in_json_string_round_float(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "values": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "apply_function_on_field_in_json_string",
                    "x-anonymize-args": [{
                                "target_field": "content_type",
                                "function": "round_float",
                                "function_args": [2],
                                "cast_element_to": "float"
                    }]
                }
              }
            }
        """

        test_json_str = """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\":\\"this_month\\",\\"content_type\\":\\"123.2312\\"}"
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\": \\"this_month\\", \\"content_type\\": 123.23}"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_apply_function_on_field_in_json_string_round_float_null(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "values": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "apply_function_on_field_in_json_string",
                    "x-anonymize-args": [{
                                "target_field": "content_type",
                                "function": "round_float",
                                "function_args": [2],
                                "cast_element_to": "float"
                    }]
                }
              }
            }
        """

        test_json_str = """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\":\\"this_month\\",\\"content_type\\":\\"not_a_number\\"}"
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\": \\"this_month\\", \\"content_type\\": null}"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_apply_function_on_field_in_json_string_missing_key(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "values": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "x-anonymize-operation": "apply_function_on_field_in_json_string",
                    "x-anonymize-args": [{
                                "target_field": "content_type",
                                "function": "encrypt"
                    }]
                }
              }
            }
        """

        test_json_str = """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\":\\"this_month\\",\\"not_content_type\\":\\"value\\"}"
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "values": "{\\"time_frame\\": \\"this_month\\", \\"not_content_type\\": \\"value\\"}"
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_encrypt_integer(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "event_id": {
                  "type": "string"
                },
                "legacy_id": {
                    "type": [
                        "string",
                        "integer",
                        "null"
                    ],
                    "x-anonymize-operation": "encrypt"
                }
              }
            }
        """

        test_json_str = """
            {
              "event_id": "user",
              "legacy_id": 1234567
            }
        """

        expected_json = json.loads(
            """
            {
              "event_id": "user",
              "legacy_id": "Zh7hpRitlY7ANahH3RDk7w=="
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_convert_to_field_length_array(self):
        schema_str = """
        {
          "$schema": "http://json-schema.org/draft-04/schema#",
          "type": "object",
          "properties": {
            "sessions": {
              "type": "array",
              "items": {
                  "type": "object",
                  "properties": {
                    "id": {
                      "type": "integer"
                    },
                    "lat": {
                      "type": "number"
                    }
                  }
              },
              "x-anonymize-operation": "convert_to_field_length"
            }
          }
        }
        """

        test_json_str = """
            {
              "sessions": [
                {"id": 333, "lat": 100.222},
                {"id": 334, "lat": 100.333}
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "sessions": 2
            }
        """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str)
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_convert_to_field_length_string(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "content": {
                    "type": [
                        "string",
                        "integer",
                        "null"
                    ],
                    "x-anonymize-operation": "convert_to_field_length"
                }
              }
            }
        """

        test_json_str = """
            {
              "content": "test"
            }
        """

        expected_json = json.loads(
            """
            {
              "content": 4
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_operation_invalid_path(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "features": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "x-anonymize-operation": "conditional_operation",
                    "x-anonymize-args": [
                        {
                            "function": "encrypt",
                            "target_field": "attributes.source_content.id",
                            "conditional_fields": "type",
                            "conditional_field_values_when_null": "",
                            "conditional_values": "story_run",
                            "conditional_operators": "!="
                        }
                    ],
                    "properties": {
                      "type": {
                        "type": "string"
                      },
                      "attributes": {
                        "type": "object",
                        "properties": {
                          "source_content": {
                            "type": "object",
                            "properties": {
                              "id": {
                                "type": "string"
                              },
                              "name": {
                                "type": "string"
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
        """

        test_json_str = """
            {
              "features": [
                {
                  "type": "story_run",
                  "attributes": {
                    "source_content": {
                      "id": "12",
                      "name": "test_name"
                    }
                  }
                },
                {
                  "type": "no_story_run",
                  "attributes": {
                    "source_content": {
                      "id": "12",
                      "name": "test_name"
                    }
                  }
                },
                {
                  "type": "no_story_run",
                  "attributes": {
                    "name": "name"
                  }
                }
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "features": [
                {
                  "type": "story_run",
                  "attributes": {
                    "source_content": {
                      "id": "12",
                      "name": "test_name"
                    }
                  }
                },
                {
                  "type": "no_story_run",
                  "attributes": {
                    "source_content": {
                      "id": "J4aEwuPScw73+k9UByEOmw==",
                      "name": "test_name"
                    }
                  }
                },
                {
                  "type": "no_story_run",
                  "attributes": {
                    "name": "name"
                  }
                }
              ]
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)

    def test_conditional_operation_invalid_path_array(self):
        schema_str = """
            {
              "$schema": "http://json-schema.org/draft-04/schema#",
              "type": "object",
              "properties": {
                "features": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "x-anonymize-operation": "conditional_operation",
                    "x-anonymize-args": [
                        {
                            "function": "encrypt",
                            "target_field": "attributes.source_content.ids",
                            "conditional_fields": "type",
                            "conditional_field_values_when_null": "",
                            "conditional_values": "story_run",
                            "conditional_operators": "!="
                        }
                    ],
                    "properties": {
                      "type": {
                        "type": "string"
                      },
                      "attributes": {
                        "type": "object",
                        "properties": {
                          "source_content": {
                            "type": "object",
                            "properties": {
                              "ids": {
                                "type": "array",
                                "items": {
                                  "type": "string"
                                }
                              },
                              "name": {
                                "type": "string"
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
        """

        test_json_str = """
            {
              "features": [
                {
                  "type": "story_run",
                  "attributes": {
                    "source_content": {
                      "ids": [1,2,3],
                      "name": "test_name"
                    }
                  }
                },
                {
                  "type": "no_story_run",
                  "attributes": {
                    "source_content": {
                      "ids": [2,3,4],
                      "name": "test_name"
                    }
                  }
                },
                {
                  "type": "no_story_run",
                  "attributes": {
                    "name": "name"
                  }
                }
              ]
            }
        """

        expected_json = json.loads(
            """
            {
              "features": [
                {
                  "type": "story_run",
                  "attributes": {
                    "source_content": {
                      "ids": [1,2,3],
                      "name": "test_name"
                    }
                  }
                },
                {
                  "type": "no_story_run",
                  "attributes": {
                    "source_content": {
                      "ids": ["JbAbzZt+w7vv/SPXXQI4Jw==", "9htZqKFcgoVKuq2rxtHzZA==", "XqoM7JxhN5obnSMM9uNEiA=="],
                      "name": "test_name"
                    }
                  }
                },
                {
                  "type": "no_story_run",
                  "attributes": {
                    "name": "name"
                  }
                }
              ]
            }
            """
        )

        anonymizer = Anonymizer(json_schema_str=schema_str, encryption_secret="123")
        anonymized_json = anonymizer.anonymize_json_str(test_json_str)
        self.assertEqual(expected_json, anonymized_json)


if __name__ == "__main__":
    unittest.main()
