from kano.model import ReachabilityMatrix
from kano.algorithm import *
from .context import sample
from .generate import ConfigFiles
from kano.parser import ConfigParser

import unittest


class BasicTestSuite(unittest.TestCase):
    """Basic test cases."""

    def test_reachability_matrix(self):
        config = ConfigFiles()
        # to test different settings, feed in different parameters here
        config.generateConfigFiles()

        cp = ConfigParser('data/')
        containers, policies = cp.parse() # can also pass filepath into cp.parse, e.g. cp.parse('data/')
        #containers should be empty, because no container yaml

        containers = config.getPods()

        #containers, policies = sample.paper_example()

        matrix = ReachabilityMatrix.build_matrix(containers, policies)
        # Nginx -> DB, Tomcat -> Nginx, User -> Tomcat
        assert matrix[0, 1] & matrix[2, 0] & matrix[4, 2]
        # no container can be reached by all other containers
        assert all_reachable(matrix) == []
        # no internal container can reach User
        assert all_isolated(matrix) == [4]
        # (Alice, DB) <- (Bob, Nginx) / (Alice, Nginx) <- (User, User) / (Bob, Nginx) <- (Alice, Tomcat)
        assert user_crosscheck(matrix, containers, "app") == [1, 2, 3]
        # (Nginx, Tomcat) <: (Alice, Tomcat)
        # Actually the (3, 2) is wrong...
        assert policy_shadow(matrix, policies, containers) == [(2, 3), (3, 2)]


if __name__ == '__main__':
    unittest.main()
