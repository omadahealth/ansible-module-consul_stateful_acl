import unittest
import mock
import consul

import modules.consul.consul_stateful_acl as ConsulStatefulACL

class ConsulStatefulACLTestCase(unittest.TestCase):
    @mock.patch('ansible.module_utils.basic.AnsibleModule')
    def setUp(self, mock_module):
        self.module = mock_module
        self.module.params = dict()

    def test_execute(self):
        '''
        Exercise ConsulStatefulACL.execute

        Set up with valid module parameters
        '''
        valid_token = "4E61EEC2-ABCC-4478-AE94-F3F35D6B0436"
        self.module.params = dict(username='jean_q_platform',
                                    host_uri="https://localhost",
                                    mgmt_token=valid_token)
        subject = ConsulStatefulACL.execute(self.module)
        expected_exit_params = dict(changed=False)
        self.module.exit_json.assert_called_once_with(**expected_exit_params)

    def test_execute_w_invalid_params(self):
        '''
        Exercise ConsulStatefulACL.execute parameter validation

        Set up with invalid module parameters
        '''
        invalid_token = "something_that_isnt_a_token"
        self.module.params = dict(username='jean_q_platform',
                                    host_uri="https://localhost",
                                    mgmt_token=invalid_token)
        subject = ConsulStatefulACL.execute(self.module)
        expected_exit_params = dict(msg="Passed token, %s, is not a valid token!" % invalid_token)
        self.module.fail_json.assert_called_once_with(**expected_exit_params)

    def test_get_consul_session(self):
        '''
        Exercise ConsulStatefulACL.get_consul_session

        Set up with valid URI
        '''
        subject = ConsulStatefulACL.get_consul_session('http://localhost:8500','2E2CB640-1B85-4413-B6F8-3303AC96CB91')
        self.assertIsInstance(subject, consul.Consul)
