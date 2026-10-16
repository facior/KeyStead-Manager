"""
Wszystkie usługi serwera w jednym miejscu – współdzielone przez API urządzeń i panel administratora.
"""

import os
from dataclasses import dataclass

from server.accounts import AdminStore, AuditLog, EnrollmentStore, UserStore
from server.attachments import AttachmentStore
from server.offboarding import OffboardingStore
from server.report_pdf import ReportHistory, org_rows, org_summary
from server.config import ServerConfig
from server.devices import DeviceRegistry
from server.notify import Notifier
from server.ops import AppDownload, BackgroundTasks, BackupService, OpsState, ReportStore
from server.settings import SettingsStore
from server.storage import VaultStore
from server.updater import UpdateBridge, UpdaterPaths

LOGO_MAX_BYTES = 256 * 1024
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@dataclass
class ServerContext:
    config: ServerConfig
    store: VaultStore
    devices: DeviceRegistry
    users: UserStore
    admins: AdminStore
    enrollments: EnrollmentStore
    audit: AuditLog
    settings: SettingsStore
    notifier: Notifier
    reports: ReportStore
    backups: BackupService
    ops_state: OpsState
    tasks: BackgroundTasks
    updates: UpdateBridge = None
    app_download: AppDownload = None
    attachments: AttachmentStore = None
    offboarding: OffboardingStore = None
    report_history: ReportHistory = None

    def download_link(self) -> str:
        """Link do pobrania aplikacji podawany użytkownikom (przez serwer – działa też bez dostępu do panelu)."""
        base = self.public_url()
        return f"{base}/download" if base else self.app_download.url()

    @property
    def logo_path(self) -> str:
        return os.path.join(self.config.data_dir, "branding", "logo.png")

    def public_url(self) -> str:
        return self.settings.section("general").get("public_url") or self.config.public_url

    def server_name(self) -> str:
        company = self.settings.section("branding").get("company_name")
        return f"KeyStead Server – {company}" if company else "KeyStead Server"

    def apply_runtime_settings(self) -> None:
        """Ustawienia z panelu, które wpływają na działające usługi."""
        general = self.settings.section("general")
        self.store.max_history = max(1, int(general.get("max_history", self.config.max_history)))

    @classmethod
    def create(cls, config: ServerConfig) -> "ServerContext":
        store = VaultStore(config.data_dir, config.max_history)
        settings = SettingsStore(config.data_dir)
        # Pierwsze uruchomienie: wartości z server.env stają się punktem wyjścia ustawień panelu
        if "general" not in settings.file.load():
            settings.update("general", {"max_history": config.max_history,
                                        "enrollment_ttl_hours": config.enrollment_ttl_hours})
        audit = AuditLog(config.data_dir)
        backups = BackupService(config.data_dir)
        ops_state = OpsState(config.data_dir)
        ctx = cls(
            config=config, store=store, devices=DeviceRegistry(config.data_dir), users=UserStore(config.data_dir),
            admins=AdminStore(config.data_dir), enrollments=EnrollmentStore(config.data_dir), audit=audit,
            settings=settings, notifier=None, reports=ReportStore(config.data_dir), backups=backups,
            ops_state=ops_state, tasks=BackgroundTasks(config.data_dir, settings, backups, audit, ops_state),
        )
        ctx.notifier = Notifier(settings, ctx.server_name)
        ctx.updates = UpdateBridge(UpdaterPaths.from_env(config.data_dir))
        ctx.tasks.updates = ctx.updates
        ctx.app_download = AppDownload(settings)
        ctx.attachments = AttachmentStore(config.data_dir)
        ctx.offboarding = OffboardingStore(config.data_dir)
        ctx.report_history = ReportHistory(config.data_dir)
        ctx.tasks.snapshot = lambda: ctx.report_history.record(org_summary(org_rows(ctx)))
        audit.add_listener(ctx.notifier.on_audit_event)
        ctx.apply_runtime_settings()
        return ctx
