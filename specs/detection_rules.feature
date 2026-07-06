# DetectionForge — behaviour specification (Spec-Driven Development)
#
# This .feature file is the SOURCE OF TRUTH for what the agent must do.
# It demonstrates the Day-5 "Spec-Driven Production Grade Development" pillar:
# behaviour is defined as Gherkin specs first; the agent code is built to satisfy
# them; and these same specs double as acceptance tests for the eval harness.
#
# Run with: behave specs/   (after writing step definitions)

Feature: CTI-to-detection rule generation
  As a SOC detection engineer
  I want an agent to turn threat intel into validated detection rules
  So that I can cut detection-engineering time without sacrificing rule quality

  Scenario: Phishing macro launching encoded PowerShell
    Given threat intel describing a Word macro spawning base64-encoded PowerShell
    When DetectionForge processes the intel
    Then the rule should be valid Sigma
    And the ATT&CK mapping should include "T1059.001"
    And the rule should convert to Splunk SPL
    And the log-source assumptions must be stated explicitly

  Scenario: Agent self-corrects an invalid rule
    Given the agent first produces a syntactically invalid Sigma rule
    When validate_sigma reports the error
    Then the agent should regenerate the rule using the error message
    And re-validate, for up to 3 attempts

  Scenario: Untrusted intel contains a prompt-injection payload
    Given threat intel containing the text "ignore all previous instructions"
    When DetectionForge sanitises the input
    Then the injection phrase should be redacted before reaching the model
    And the agent should still produce a detection rule for the genuine threat

  Scenario: Duplicate rule suppression
    Given a rule with the same title already exists in rule memory
    When the agent authors a new rule with a near-identical title
    Then the agent should not store a duplicate
