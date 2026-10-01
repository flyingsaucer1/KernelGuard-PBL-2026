from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class User(Model):
    uid: str = Field(pattern=r"^\d{1,10}$")
    username: str = Field(min_length=1, max_length=128)


class Process(Model):
    pid: int = Field(gt=0)
    ppid: int = Field(ge=0)
    started: str = Field(pattern=r"^\d{1,16}(\.\d{1,6})?$", max_length=32)
    uid: str = Field(pattern=r"^\d{1,10}$")
    effective_uid: str = Field(pattern=r"^\d{1,10}$")
    login_uid: str | None = Field(default=None, pattern=r"^\d{1,10}$")
    session: str | None = Field(default=None, pattern=r"^\d{1,10}$")
    executable: str | None = Field(default=None, max_length=4096)


class Device(Model):
    vendor: str = Field(pattern=r"^[0-9a-f]{4}$")
    product: str = Field(pattern=r"^[0-9a-f]{4}$")
    serial: str | None = Field(default=None, min_length=1, max_length=256)
    port: str = Field(min_length=1, max_length=256)
    label: str = Field(min_length=1, max_length=256)


class Snapshot(Model):
    host: str = Field(min_length=1, max_length=128)
    origin: Literal["demo", "live"]
    boot_id: str = Field(min_length=1, max_length=64)
    timestamp: int = Field(gt=0)
    users: list[User] = Field(max_length=100000)
    processes: list[Process] = Field(max_length=100000)
    devices: list[Device] = Field(max_length=10000)
    processes_complete: bool = True
    warnings: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_identities(self):
        if len({u.uid for u in self.users}) != len(self.users):
            raise ValueError("Duplicate user UID in snapshot")
        if len({p.pid for p in self.processes}) != len(self.processes):
            raise ValueError("Duplicate process PID in snapshot")
        identities = [(d.vendor, d.product, d.serial or d.port) for d in self.devices]
        if len(set(identities)) != len(identities):
            raise ValueError("Ambiguous duplicate USB identities; snapshot rejected")
        return self
