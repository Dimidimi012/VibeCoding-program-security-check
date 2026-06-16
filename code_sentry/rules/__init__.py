from code_sentry.rules.base import Rule, Finding, ScanResult, Severity, Category
from code_sentry.rules.poisoning import POISONING_RULES
from code_sentry.rules.security import SECURITY_RULES


def get_all_rules() -> list[Rule]:
    return POISONING_RULES + SECURITY_RULES
