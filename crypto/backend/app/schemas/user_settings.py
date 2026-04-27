import base64
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


THEME_VALUES = Literal["dark", "light", "system"]
FONT_SIZE_VALUES = Literal["small", "default", "large", "xlarge"]
EDITOR_MODE_VALUES = Literal["wysiwyg", "markdown"]
STARTUP_VIEW_VALUES = Literal["last", "all", "folder"]
LANGUAGE_VALUES = Literal["en", "tr"]
DATE_FORMAT_VALUES = Literal["relative", "absolute", "iso"]
DENSITY_VALUES = Literal["compact", "comfortable", "spacious"]


def _validate_b64(value: str) -> str:
    try:
        base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise ValueError(f"Field must be valid base64: {e}") from e
    return value


class EncryptionSetupSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    salt: str = Field(..., min_length=20, max_length=32)
    wrappedDek: str = Field(..., min_length=20)
    dekIv: str = Field(..., min_length=16, max_length=20)
    verify: Optional[str] = Field(default=None, min_length=20)
    verifyIv: Optional[str] = Field(default=None, min_length=16, max_length=20)

    @field_validator("salt", "wrappedDek", "dekIv", "verify", "verifyIv")
    @classmethod
    def validate_base64(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _validate_b64(v)


class UserPreferencesResponse(BaseModel):
    theme: str
    font_size: str
    editor_mode: str
    startup_view: str
    language: str
    date_format: str
    timezone: str
    profession_raw: Optional[str] = None
    profession_category: Optional[str] = None
    profession_subcategory: Optional[str] = None
    profession_secondary: Optional[str] = None
    profession_workflows: Optional[list[str]] = None
    profession_confidence: Optional[float] = None
    profession_source: Optional[str] = None
    encryption_setup: Optional[dict] = None
    feature_toggles: Optional[dict] = None
    voice_settings: Optional[dict] = None
    ai_behavior: Optional[dict] = None
    editor_settings: Optional[dict] = None
    accessibility_settings: Optional[dict] = None
    privacy_settings: Optional[dict] = None
    search_history_retention_days: int = 90

    class Config:
        from_attributes = True


class UserPreferencesUpdate(BaseModel):
    theme: Optional[THEME_VALUES] = None
    font_size: Optional[FONT_SIZE_VALUES] = None
    editor_mode: Optional[EDITOR_MODE_VALUES] = None
    startup_view: Optional[STARTUP_VIEW_VALUES] = None
    language: Optional[LANGUAGE_VALUES] = None
    date_format: Optional[DATE_FORMAT_VALUES] = None
    timezone: Optional[str] = Field(None, max_length=50)
    profession_raw: Optional[str] = Field(None, max_length=500)
    encryption_setup: Optional[EncryptionSetupSchema] = None
    feature_toggles: Optional[dict] = None
    voice_settings: Optional[dict] = None
    ai_behavior: Optional[dict] = None
    editor_settings: Optional[dict] = None
    accessibility_settings: Optional[dict] = None
    privacy_settings: Optional[dict] = None
    search_history_retention_days: Optional[int] = Field(
        None, ge=0, le=3650, description="0 means 'do not retain'."
    )


DIGEST_FREQ_VALUES = Literal["daily", "weekly", "none"]


class NotificationPreferencesResponse(BaseModel):
    email_note_shared: bool
    email_note_edited: bool
    email_weekly_digest: bool
    email_mcp_activity: bool
    email_daily_digest: bool
    email_comment_reply: bool
    email_workspace_invite: bool
    email_security_alerts: bool
    inapp_note_mentions: bool
    inapp_share_requests: bool
    inapp_mcp_alerts: bool
    inapp_collaboration: bool
    inapp_workspace: bool
    inapp_system: bool
    inapp_new_login_alert: bool = True
    email_new_login_alert: bool = True
    push_enabled: bool
    push_collaboration: bool
    push_mentions: bool
    quiet_hours_start: Optional[str] = None
    quiet_hours_end: Optional[str] = None
    digest_frequency: str
    digest_time: Optional[str] = Field(
        None,
        description=(
            "Per-user digest delivery hour (HH:MM, UTC). NULL falls back "
            "to the legacy 08:00 UTC cron during the dynamic-scheduler "
            "rollout."
        ),
    )
    digest_day_of_week: Optional[int] = Field(
        None, ge=0, le=6, description="0=Mon … 6=Sun"
    )
    quiet_hours_per_day: Optional[dict] = None
    per_event_channels: Optional[dict] = None
    marketing_emails_opt_in: bool = False

    class Config:
        from_attributes = True


class NotificationPreferencesUpdate(BaseModel):
    email_note_shared: Optional[bool] = None
    email_note_edited: Optional[bool] = None
    email_weekly_digest: Optional[bool] = None
    email_mcp_activity: Optional[bool] = None
    email_daily_digest: Optional[bool] = None
    email_comment_reply: Optional[bool] = None
    email_workspace_invite: Optional[bool] = None
    email_security_alerts: Optional[bool] = None
    inapp_note_mentions: Optional[bool] = None
    inapp_share_requests: Optional[bool] = None
    inapp_mcp_alerts: Optional[bool] = None
    inapp_collaboration: Optional[bool] = None
    inapp_workspace: Optional[bool] = None
    inapp_system: Optional[bool] = None
    inapp_new_login_alert: Optional[bool] = None
    email_new_login_alert: Optional[bool] = None
    push_enabled: Optional[bool] = None
    push_collaboration: Optional[bool] = None
    push_mentions: Optional[bool] = None
    quiet_hours_start: Optional[str] = Field(None, pattern=r"^\d{2}:\d{2}$")
    quiet_hours_end: Optional[str] = Field(None, pattern=r"^\d{2}:\d{2}$")
    digest_frequency: Optional[DIGEST_FREQ_VALUES] = None
    digest_time: Optional[str] = Field(None, pattern=r"^\d{2}:\d{2}$")
    digest_day_of_week: Optional[int] = Field(None, ge=0, le=6)
    quiet_hours_per_day: Optional[dict] = Field(
        None,
        description=(
            "JSONB blob of weekday/weekend overrides. Service layer deep "
            "merges; pass ``{}`` to clear."
        ),
    )
    per_event_channels: Optional[dict] = Field(
        None,
        description=(
            "Per-event channel routing matrix. Shape: "
            "``{event_key: {email: bool, in_app: bool, push: bool}}``."
        ),
    )
    marketing_emails_opt_in: Optional[bool] = None

    @field_validator("digest_time")
    @classmethod
    def validate_digest_time(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        hh_str, mm_str = v.split(":")
        hh, mm = int(hh_str), int(mm_str)
        if not (0 <= hh <= 23 and 0 <= mm <= 59):
            raise ValueError("digest_time must be HH:MM in 00:00..23:59")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str = ""
    new_password: str = Field(..., min_length=8)


class ChangeEmailRequest(BaseModel):
    new_email: EmailStr
    password: str


class DeleteAccountRequest(BaseModel):
    password: str
    confirmation: str = Field(..., description='Must be "delete my account"')


class Setup2FAResponse(BaseModel):
    secret: str
    qr_uri: str


class Confirm2FARequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6)


class Confirm2FAResponse(BaseModel):
    backup_codes: list[str]


class Disable2FARequest(BaseModel):
    password: str
    totp_code: str = Field(..., min_length=6, max_length=6)


class SessionResponse(BaseModel):
    session_id: str
    device: str
    browser: Optional[str] = None
    os: Optional[str] = None
    ip_address: str = ""
    location: Optional[str] = None
    last_active: datetime
    is_current: bool
    device_id: Optional[int] = None


class SessionListResponse(BaseModel):
    items: list[SessionResponse]


class DeviceResponse(BaseModel):
    id: int
    browser: Optional[str] = None
    browser_version: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    display_label: str
    location: Optional[str] = None
    first_seen_at: str
    last_seen_at: str
    trusted: bool


class DeviceListResponse(BaseModel):
    items: list[DeviceResponse]
