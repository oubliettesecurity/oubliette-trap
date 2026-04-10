"""Tests for DeceptionProfile and EnvironmentState."""
import pytest
from oubliette.deception.profile import DeceptionProfile, EnvironmentState


class TestEnvironmentState:
    def test_has_consistent_hostnames(self):
        state = EnvironmentState.generate()
        assert len(state.hostnames) >= 4
        assert all(isinstance(h, str) for h in state.hostnames)

    def test_has_consistent_users(self):
        state = EnvironmentState.generate()
        assert len(state.usernames) >= 3
        assert all(isinstance(u, str) for u in state.usernames)

    def test_has_services(self):
        state = EnvironmentState.generate()
        assert len(state.services) >= 4
        for svc in state.services:
            assert "name" in svc
            assert "host" in svc
            assert "port" in svc

    def test_services_reference_hostnames(self):
        state = EnvironmentState.generate()
        hosts = set(state.hostnames)
        for svc in state.services:
            assert svc["host"] in hosts

    def test_credentials_reference_users(self):
        state = EnvironmentState.generate()
        users = set(state.usernames)
        for cred in state.credentials:
            assert cred["username"] in users

    def test_two_generations_differ(self):
        s1 = EnvironmentState.generate()
        s2 = EnvironmentState.generate()
        assert s1.hostnames != s2.hostnames


class TestDeceptionProfile:
    def test_create_default(self):
        profile = DeceptionProfile(name="test")
        assert profile.name == "test"
        assert profile.state is not None

    def test_get_tool_names(self):
        profile = DeceptionProfile(name="test")
        tools = profile.get_tool_names()
        assert isinstance(tools, list)
        assert len(tools) >= 10

    def test_get_tool_response_uses_shared_state(self):
        profile = DeceptionProfile(name="test")
        resp = profile.get_tool_response("list_services", {})
        resp_str = str(resp)
        assert any(h in resp_str for h in profile.state.hostnames)
