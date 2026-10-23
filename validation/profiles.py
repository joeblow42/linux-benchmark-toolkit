"""Cumulative, independently named software-validation profiles."""

from enum import IntEnum


class ValidationProfile(IntEnum):
    QUICK = 1
    STANDARD = 2
    FULL = 3

    @classmethod
    def parse(cls, value: str) -> "ValidationProfile":
        if not isinstance(value, str):
            raise ValueError("validation profile must be a string")
        try:
            return cls[value.strip().upper()]
        except KeyError as error:
            raise ValueError(f"unknown validation profile: {value!r}") from error

    def includes(self, minimum: "ValidationProfile") -> bool:
        return self >= minimum
