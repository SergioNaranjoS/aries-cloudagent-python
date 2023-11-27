@RFC0453
Feature: RFC 0453 Aries agent issue credential

  @T004-RFC0453 @GHA-Anoncreds-skip-revoc
  Scenario Outline: Using anoncreds, Issue a credential with revocation, with the Issuer beginning with an offer, and then revoking the credential
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And Using anoncreds, "Bob" has an issued <Schema_name> credential <Credential_data> from "Acme"
    Then Using anoncreds, "Acme" revokes the credential
    And "Bob" has the credential issued

    Examples:
       | Acme_capabilities                        | Bob_capabilities  | Schema_name    | Credential_data          |
       | --revocation --cred-type anoncreds --public-did |            | anoncreds-testing | Data_AC_NormalizedValues |
       | --revocation --cred-type anoncreds --public-did --did-exchange | --did-exchange| anoncreds-testing | Data_AC_NormalizedValues |
       | --revocation --cred-type anoncreds --public-did --multitenant  | --multitenant | anoncreds-testing | Data_AC_NormalizedValues |

  @T004-RFC0453 @GHA
  Scenario Outline: Using anoncreds, create a schema/cred def in preparation for Issuing a credential
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And Using anoncreds, "Acme" is ready to issue a credential for <Schema_name>

    Examples:
       | Acme_capabilities                                                | Bob_capabilities              | Schema_name       | Credential_data          |
       | --cred-type anoncreds --public-did --wallet-type askar-anoncreds | --wallet-type askar-anoncreds | anoncreds-testing | Data_AC_NormalizedValues |

  @T004-RFC0453 @GHA-Anoncreds-test1
  Scenario Outline: Using anoncreds, Issue a credential, with the Issuer beginning with an offer
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And Using anoncreds, "Bob" has an issued <Schema_name> credential <Credential_data> from "Acme"
    Then "Bob" has the credential issued

    Examples:
       | Acme_capabilities                                                | Bob_capabilities              | Schema_name       | Credential_data          |
       | --cred-type anoncreds --public-did --wallet-type askar-anoncreds | --wallet-type askar-anoncreds | anoncreds-testing | Data_AC_NormalizedValues |

  @T003-RFC0453 @GHA
  Scenario Outline: Issue a credential with the Issuer beginning with an offer
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And "Acme" is ready to issue a credential for <Schema_name>
    When "Acme" offers a credential with data <Credential_data>
    Then "Bob" has the credential issued

    Examples:
       | Acme_capabilities                      | Bob_capabilities          | Schema_name    | Credential_data          |
       | --public-did                           |                           | driverslicense | Data_DL_NormalizedValues |
       | --public-did --did-exchange            | --did-exchange            | driverslicense | Data_DL_NormalizedValues |
       | --public-did --mediation               | --mediation               | driverslicense | Data_DL_NormalizedValues |
       | --public-did --multitenant             | --multitenant             | driverslicense | Data_DL_NormalizedValues |

  @T003-RFC0453 @GHA
  Scenario Outline: Holder accepts a deleted credential offer
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And "Acme" is ready to issue a credential for <Schema_name>
    And "Acme" offers and deletes a credential with data <Credential_data>
    Then "Bob" has the exchange abandoned

    Examples:
       | Acme_capabilities                      | Bob_capabilities          | Schema_name    | Credential_data          |
       | --public-did                           |                           | driverslicense | Data_DL_NormalizedValues |
       #| --public-did --did-exchange            | --did-exchange            | driverslicense | Data_DL_NormalizedValues |
       #| --public-did --mediation               | --mediation               | driverslicense | Data_DL_NormalizedValues |
       #| --public-did --multitenant             | --multitenant             | driverslicense | Data_DL_NormalizedValues |

  @T003-RFC0453 @GHA
  Scenario Outline: Issue a credential with the holder sending a request
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And "Acme" is ready to issue a credential for <Schema_name>
    When "Bob" requests a credential with data <Credential_data> from "Acme" it fails

    Examples:
       | Acme_capabilities                      | Bob_capabilities          | Schema_name    | Credential_data          |
       | --public-did                           |                           | driverslicense | Data_DL_NormalizedValues |
       #| --public-did --did-exchange            | --did-exchange            | driverslicense | Data_DL_NormalizedValues |
       #| --public-did --mediation               | --mediation               | driverslicense | Data_DL_NormalizedValues |
       #| --public-did --multitenant             | --multitenant             | driverslicense | Data_DL_NormalizedValues |


  @T003.1-RFC0453 @GHA
  Scenario Outline: Holder accepts a deleted json-ld credential offer
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And "Acme" is ready to issue a json-ld credential for <Schema_name>
    And "Bob" is ready to receive a json-ld credential
    When "Acme" offers and deletes "Bob" a json-ld credential with data <Credential_data>
    Then "Bob" has the json-ld credential issued
    And "Acme" has the exchange completed

    Examples:
       | Acme_capabilities                                   | Bob_capabilities          | Schema_name    | Credential_data          |
       | --public-did --cred-type json-ld                    |                           | driverslicense | Data_DL_NormalizedValues |
       # | --public-did --cred-type json-ld --did-exchange     | --did-exchange            | driverslicense | Data_DL_NormalizedValues |
       # | --public-did --cred-type json-ld --mediation        | --mediation               | driverslicense | Data_DL_NormalizedValues |
       # | --public-did --cred-type json-ld --multitenant      | --multitenant             | driverslicense | Data_DL_NormalizedValues |

  @T003.1-RFC0453 @GHA-Anoncreds-update @GHA
  Scenario Outline: Issue a json-ld credential with the Issuer beginning with an offer
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And "Acme" is ready to issue a json-ld credential for <Schema_name>
    And "Bob" is ready to receive a json-ld credential
    When "Acme" offers "Bob" a json-ld credential with data <Credential_data>
    Then "Bob" has the json-ld credential issued

    Examples:
       | Acme_capabilities                                   | Bob_capabilities          | Schema_name    | Credential_data          |
       | --public-did --cred-type json-ld                    |                           | driverslicense | Data_DL_NormalizedValues |
       | --public-did --cred-type json-ld --did-exchange     | --did-exchange            | driverslicense | Data_DL_NormalizedValues |
       | --public-did --cred-type json-ld --mediation        | --mediation               | driverslicense | Data_DL_NormalizedValues |
       | --public-did --cred-type json-ld --multitenant      | --multitenant             | driverslicense | Data_DL_NormalizedValues |


  @T003.1-RFC0453 @GHA
  Scenario Outline: Issue a json-ld credential with the holder beginning with a request
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And "Acme" is ready to issue a json-ld credential for <Schema_name>
    And "Bob" is ready to receive a json-ld credential
    When "Bob" requests a json-ld credential with data <Credential_data> from "Acme"
    Then "Bob" has the json-ld credential issued

    Examples:
       | Acme_capabilities                                   | Bob_capabilities          | Schema_name    | Credential_data          |
       | --public-did --cred-type json-ld                    |                           | driverslicense | Data_DL_NormalizedValues |
       | --public-did --cred-type json-ld --did-exchange     | --did-exchange            | driverslicense | Data_DL_NormalizedValues |
       | --public-did --cred-type json-ld --mediation        | --mediation               | driverslicense | Data_DL_NormalizedValues |
       | --public-did --cred-type json-ld --multitenant      | --multitenant             | driverslicense | Data_DL_NormalizedValues |


  @T004-RFC0453 @GHA-Anoncreds-update @GHA
  Scenario Outline: Issue a credential with revocation, with the Issuer beginning with an offer, and then revoking the credential
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And "Bob" has an issued <Schema_name> credential <Credential_data> from "Acme"
    Then "Acme" revokes the credential
    And "Bob" has the credential issued

    Examples:
       | Acme_capabilities                        | Bob_capabilities  | Schema_name    | Credential_data          |
       | --revocation --public-did                |                   | driverslicense | Data_DL_NormalizedValues |
       | --revocation --public-did --did-exchange | --did-exchange    | driverslicense | Data_DL_NormalizedValues |
       | --revocation --public-did --multitenant  | --multitenant     | driverslicense | Data_DL_NormalizedValues |

  @T004.1-RFC0453
  Scenario Outline: Issue a credential with revocation, with the Issuer beginning with an offer, and then revoking the credential
    Given we have "2" agents
      | name  | role    | capabilities        |
      | Acme  | issuer  | <Acme_capabilities> |
      | Bob   | holder  | <Bob_capabilities>  |
    And "Acme" and "Bob" have an existing connection
    And "Bob" has an issued <Schema_name> credential <Credential_data> from "Acme"
    Then "Acme" revokes the credential
    And "Bob" has the credential issued

    Examples:
       | Acme_capabilities                        | Bob_capabilities  | Schema_name    | Credential_data          |
       | --revocation --public-did --mediation    | --mediation       | driverslicense | Data_DL_NormalizedValues |
