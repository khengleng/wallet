"""Operations and workflow view exports (phase 1 split from monolithic views module)."""

from . import views as legacy

ops_work_queue = legacy.ops_work_queue
approval_matrix = legacy.approval_matrix
documents_center = legacy.documents_center
settlement_operations = legacy.settlement_operations
reconciliation_workbench = legacy.reconciliation_workbench
operations_reports = legacy.operations_reports
operations_settings = legacy.operations_settings
policy_hub = legacy.policy_hub
operations_center = legacy.operations_center
case_detail = legacy.case_detail
treasury_dashboard = legacy.treasury_dashboard
treasury_decision = legacy.treasury_decision
approval_decision = legacy.approval_decision
