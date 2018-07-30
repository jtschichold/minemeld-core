import json

from collections import namedtuple

import yaml


__all__ = [
    'CHANGE_ADDED', 'CHANGE_DELETED',
    'CHANGE_INPUT_ADDED', 'CHANGE_INPUT_DELETED',
    'CHANGE_OUTPUT_ENABLED', 'CHANGE_OUTPUT_DISABLED'
]


CHANGE_ADDED = 0
CHANGE_DELETED = 1
CHANGE_INPUT_ADDED = 2
CHANGE_INPUT_DELETED = 3
CHANGE_OUTPUT_ENABLED = 4
CHANGE_OUTPUT_DISABLED = 5


ConfigChange = namedtuple(
    'ConfigChange',
    ['nodename', 'nodeclass', 'change', 'detail']
)

Config = namedtuple(
    'Config',
    ['nodes', 'changes']
)


class MineMeldConfigChange(ConfigChange):
    def __new__(_cls, nodename, nodeclass, change, detail=None):
        return ConfigChange.__new__(
            _cls,
            nodename=nodename,
            nodeclass=nodeclass,
            change=change,
            detail=detail
        )


class MineMeldConfig(Config):
    """MineMeld Engine configuration
    """

    def as_nset(self):
        """Translate config in a set of tuples (node name, node class) serialized in JSON
        
        Returns:
            set: see description
        """

        result = set()
        for nname, nvalue in self.nodes.items():
            result.add(
                json.dumps(
                    [nname, nvalue.get('class', None)],
                    sort_keys=True
                )
            )
        return result

    def compute_changes(self, oconfig):
        """Compute changes compared to an old configuration. Set the changes attributes
        with the result.
        
        Args:
            oconfig (MineMeldConfig): old configuration
        """

        if oconfig is None:
            # oconfig is None, mark everything as added
            for nodename, nodeattrs in self.nodes.items():
                self.changes.append(
                    MineMeldConfigChange(nodename=nodename, nodeclass=nodeattrs['class'], change=CHANGE_ADDED)
                )
            return

        my_nset = self.as_nset()
        other_nset = oconfig.as_nset()

        deleted = other_nset - my_nset
        added = my_nset - other_nset
        untouched = my_nset & other_nset

        # mark delted as deleted
        for snode in deleted:
            nodename, nodeclass = json.loads(snode)
            change = MineMeldConfigChange(
                nodename=nodename,
                nodeclass=nodeclass,
                change=CHANGE_DELETED,
                detail=oconfig.nodes[nodename]
            )
            self.changes.append(change)

        # mark added as added
        for snode in added:
            nodename, nodeclass = json.loads(snode)
            change = MineMeldConfigChange(
                nodename=nodename,
                nodeclass=nodeclass,
                change=CHANGE_ADDED
            )
            self.changes.append(change)

        # check inputs/output for untouched
        for snode in untouched:
            nodename, nodeclass = json.loads(snode)

            my_inputs = set(self.nodes[nodename].get('inputs', []))
            other_inputs = set(oconfig.nodes[nodename].get('inputs', []))

            iadded = my_inputs - other_inputs
            ideleted = other_inputs - my_inputs

            for i in iadded:
                change = MineMeldConfigChange(
                    nodename=nodename,
                    nodeclass=nodeclass,
                    change=CHANGE_INPUT_ADDED,
                    detail=i
                )
                self.changes.append(change)

            for i in ideleted:
                change = MineMeldConfigChange(
                    nodename=nodename,
                    nodeclass=nodeclass,
                    change=CHANGE_INPUT_DELETED,
                    detail=i
                )
                self.changes.append(change)

            my_output = self.nodes[nodename].get('output', False)
            other_output = oconfig.nodes[nodename].get('output', False)

            if my_output == other_output:
                continue

            change_type = CHANGE_OUTPUT_DISABLED
            if my_output:
                change_type = CHANGE_OUTPUT_ENABLED

            change = MineMeldConfigChange(
                nodename=nodename,
                nodeclass=nodeclass,
                change=change_type
            )
            self.changes.append(change)

    @classmethod
    def from_dict(cls, dconfig=None):
        """Create a new MineMeldConfig instance from a dict config

        Args:
            dconfig (dict, optional): Defaults to None. Config in dict format
        
        Returns:
            MineMeldConfig: the instance of MineMeldConfig
        """

        if dconfig is None:
            dconfig = {}

        nodes = dconfig.get('nodes', None)
        if nodes is None:
            nodes = {}

        return cls(nodes=nodes, changes=[])

    @classmethod
    def from_file(cls, f):
        """Create a new MineMeldConfig instance from a YAML file
        
        Args:
            f (file): YAML file to load the config from

        Returns:
            MineMeldConfig: the instance of MineMeldConfig
        """

        config = yaml.safe_load(f)

        if not isinstance(config, dict) and config is not None:
            raise ValueError('Invalid config YAML type')

        return cls.from_dict(config)