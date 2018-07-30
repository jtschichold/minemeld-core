__all__ = ['compare', 'diff_dicts']


def _is_list_equal(A, B):
    # we assume that items have all the same type
    # and that if the type is int or str, unicode
    # then it's order independent, otherwise order matters
    if len(A) != len(B):
        return False

    if len(A) == 0:
        return True

    if isinstance(A[0], str) or isinstance(A[0], int) or \
       isinstance(A[0], float):
        # we sort in palce as these are just copies
        A.sort()
        B.sort()
    
    # if elements are dictionaries, we sort based on 'id'
    if isinstance(A[0], dict) and 'id' in A[0]:
        A.sort(key=lambda x: x['id'])
    if isinstance(B[0], dict) and 'id' in B[0]:
        B.sort(key=lambda x: x['id'])

    for idx in range(len(A)):
        if not compare(A[idx], B[idx]):
            return False

    return True


def _is_dict_equal(A, B):
    A_keys = list(A.keys())
    B_keys = list(B.keys())

    if not _is_list_equal(A_keys, B_keys):
        return False

    for key in A_keys:
        if not compare(A[key], B[key]):
            return False

    return True


def compare(A, B):
    """Deep compare A and B
    
    Args:
        A (any): element A
        B (any): element B
    
    Raises:
        RuntimeError: Uhandled types
    
    Returns:
        bool: is equal?
    """

    if type(A) != type(B):
        return False

    if A is None:
        return True

    if isinstance(A, bool):
        return A == B

    if isinstance(A, str):
        return A == B

    if isinstance(A, bytes):
        return A == B

    if isinstance(A, int) or isinstance(A, float):
        return A == B

    if isinstance(A, list) or isinstance(A, tuple):
        return _is_list_equal(A, B)

    if isinstance(A, dict):
        return _is_dict_equal(A, B)

    raise RuntimeError('Unhandled type {!r} in compare'.format(type(A)))


def diff_dicts(old, new):
    """Diff 2 dictionaries
    
    Args:
        old (dict): old version
        new (dict): new version
    
    Returns:
        list: list of modified keys (added, removed or changed)
    """

    result = []

    old_keys = set(old.keys())
    new_keys = set(new.keys())

    for changed_key in new_keys ^ old_keys:
        result.append(changed_key)

    for existing_key in new_keys & old_keys:
        if not compare(old[existing_key], new[existing_key]):
            result.append(existing_key)

    return result
