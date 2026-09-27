"""Tooling availability schema for the settings page."""

from __future__ import annotations

from pydantic import BaseModel


class ToolStatus(BaseModel):
    name: str
    installed: bool
    version: str | None = None
    detail: str | None = None


class ToolsData(BaseModel):
    active_reader: str
    tools: list[ToolStatus]
