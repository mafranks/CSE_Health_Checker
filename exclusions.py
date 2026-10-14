"""Read the local policy lists exposed by the original public Health Checker."""


def child_element(root, name):
    """Find a direct XML child by local name in signed, namespaced, or plain policies."""
    return next((child for child in root if child.tag.rsplit("}", 1)[-1] == name), None) if root is not None else None


def read_policy_exclusions(root):
    """Preserve the general and process lists without interpreting their encoded entries."""
    if root is None:
        raise ValueError("A policy XML root is required")
    config = next((node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "config"), None)
    lists = {"path_exclusions": [], "process_exclusions": []}
    exclusions = child_element(config, "exclusions")
    for tag, key in (("info", "path_exclusions"), ("process", "process_exclusions")):
        parent = child_element(exclusions, tag)
        if parent is not None:
            lists[key] = [node.text for node in parent if node.tag.rsplit("}", 1)[-1] == "item"]
    return lists


def policy_exclusion_entries(policy):
    """Return complete copyable entries without guessing exclusion types or child scope."""
    if not isinstance(policy, dict):
        raise ValueError("A policy dictionary is required")
    result = {}
    for display, key in (("general", "path_exclusions"), ("process", "process_exclusions")):
        values = policy.get(key) or []
        if not isinstance(values, (list, tuple)):
            raise ValueError("Policy exclusion lists must contain a sequence of entries")
        result[display] = tuple(str(value) if value is not None and value != "" else "(empty entry)" for value in values)
    return result
