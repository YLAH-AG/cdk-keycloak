// import * as fs from 'fs';
import { App, assertions, Stack } from 'aws-cdk-lib';
import * as kc from '../src';
// import '@aws-cdk/assert/jest';
import { KeycloakVersion } from '../src';
test.skip('create the default cluster', () => {
  // GIVEN
  const app = new App();
  const stack = new Stack(app, 'testing-stack');

  // WHEN
  new kc.KeyCloak(stack, 'KeyCloak', {
    certificateArn: 'MOCK_ARN',
    keycloakVersion: KeycloakVersion.V21_0_1,
  });

  // THEN
  const t = assertions.Template.fromStack(stack);
  t.hasResourceProperties('AWS::RDS::DBCluster', {
    Engine: 'aurora-mysql',
    DBClusterParameterGroupName: 'default.aurora-mysql8.0',
    DBSubnetGroupName: {
      Ref: 'KeyCloakDatabaseDBClusterSubnetsE36F1B1B',
    },
    EngineVersion: '5.7.mysql_aurora.2.09.1',
    MasterUsername: 'admin',
    MasterUserPassword: {
      'Fn::Join': [
        '',
        [
          '{{resolve:secretsmanager:',
          {
            Ref: 'testingstackKeyCloakDatabaseDBClusterSecret754146743fdaad7efa858a3daf9490cf0a702aeb',
          },
          ':SecretString:password::}}',
        ],
      ],
    },
    VpcSecurityGroupIds: [
      {
        'Fn::GetAtt': ['KeyCloakDatabaseDBClusterSecurityGroup843B4392', 'GroupId'],
      },
    ],
  });
  // we should have 2 db instances in the cluster
  t.resourceCountIs('AWS::RDS::DBInstance', 2);
  // we should have 2 secrets
  t.resourceCountIs('AWS::SecretsManager::Secret', 3);
  // we should have ecs service

  t.hasResourceProperties('AWS::ECS::Service', {
    Cluster: {
      Ref: 'KeyCloakKeyCloakContainerSerivceClusterA18E44FF',
    },
    DeploymentConfiguration: {
      MaximumPercent: 200,
      MinimumHealthyPercent: 50,
    },
    DesiredCount: 2,
    EnableECSManagedTags: false,
    HealthCheckGracePeriodSeconds: 120,
    LaunchType: 'FARGATE',
    LoadBalancers: [
      {
        ContainerName: 'keycloak',
        ContainerPort: 8080,
        TargetGroupArn: {
          Ref: 'KeyCloakKeyCloakContainerSerivceALBALBHttpsListenerECSTargetGroupA6169207',
        },
      },
    ],
    NetworkConfiguration: {
      AwsvpcConfiguration: {
        AssignPublicIp: 'DISABLED',
        SecurityGroups: [
          {
            'Fn::GetAtt': [
              'KeyCloakKeyCloakContainerSerivceServiceSecurityGroup4C80023D',
              'GroupId',
            ],
          },
        ],
        Subnets: [
          {
            Ref: 'KeyCloakVpcPrivateSubnet1SubnetA692DFFF',
          },
          {
            Ref: 'KeyCloakVpcPrivateSubnet2SubnetC8682D75',
          },
        ],
      },
    },
    TaskDefinition: {
      Ref: 'KeyCloakKeyCloakContainerSerivceTaskDef30C9533A',
    },
  });
});

test.skip('with aurora serverless', () => {
  // GIVEN
  const app = new App();
  const stack = new Stack(app, 'testing-stack');

  // WHEN
  new kc.KeyCloak(stack, 'KeyCloak', {
    certificateArn: 'MOCK_ARN',
    auroraServerless: true,
    keycloakVersion: KeycloakVersion.V21_0_1,
  });

  // THEN
  const t = assertions.Template.fromStack(stack);

  t.hasResourceProperties('AWS::RDS::DBCluster', {
    Engine: 'aurora-mysql',
    DBClusterParameterGroupName: 'default.aurora-mysql8.0',
    EngineMode: 'serverless',
  });
  // we should have 0 db instance in the cluster
  t.resourceCountIs('AWS::RDS::DBInstance', 0);
  // we should have 2 secrets
  t.resourceCountIs('AWS::SecretsManager::Secret', 3);
  // we should have ecs service
  t.hasResourceProperties('AWS::ECS::Service', {
    Cluster: {
      Ref: 'KeyCloakKeyCloakContainerSerivceClusterA18E44FF',
    },
    DeploymentConfiguration: {
      MaximumPercent: 200,
      MinimumHealthyPercent: 50,
    },
    DesiredCount: 2,
    EnableECSManagedTags: false,
    HealthCheckGracePeriodSeconds: 120,
    LaunchType: 'FARGATE',
    LoadBalancers: [
      {
        ContainerName: 'keycloak',
        ContainerPort: 8080,
        TargetGroupArn: {
          Ref: 'KeyCloakKeyCloakContainerSerivceALBALBHttpsListenerECSTargetGroupA6169207',
        },
      },
    ],
    NetworkConfiguration: {
      AwsvpcConfiguration: {
        AssignPublicIp: 'DISABLED',
        SecurityGroups: [
          {
            'Fn::GetAtt': [
              'KeyCloakKeyCloakContainerSerivceServiceSecurityGroup4C80023D',
              'GroupId',
            ],
          },
        ],
        Subnets: [
          {
            Ref: 'KeyCloakVpcPrivateSubnet1SubnetA692DFFF',
          },
          {
            Ref: 'KeyCloakVpcPrivateSubnet2SubnetC8682D75',
          },
        ],
      },
    },
    TaskDefinition: {
      Ref: 'KeyCloakKeyCloakContainerSerivceTaskDef30C9533A',
    },
  });
});

test.skip('with aurora serverless v2', () => {
  // GIVEN
  const app = new App();
  const stack = new Stack(app, 'testing-stack');

  // WHEN
  new kc.KeyCloak(stack, 'KeyCloak', {
    certificateArn: 'MOCK_ARN',
    auroraServerlessV2: true,
    keycloakVersion: KeycloakVersion.V21_0_1,
  });

  // THEN
  const t = assertions.Template.fromStack(stack);
  t.hasResourceProperties('AWS::RDS::DBCluster', {
    Engine: 'aurora-mysql',
    DBClusterParameterGroupName: 'default.aurora-mysql8.0',
    DBSubnetGroupName: {
      Ref: 'KeyCloakDatabaseDBClusterSubnetsE36F1B1B',
    },
    EngineVersion: '8.0.mysql_aurora.3.02.0',
    MasterUsername: 'admin',
    MasterUserPassword: {
      'Fn::Join': [
        '',
        [
          '{{resolve:secretsmanager:',
          {
            Ref: 'testingstackKeyCloakDatabaseDBClusterSecret754146743fdaad7efa858a3daf9490cf0a702aeb',
          },
          ':SecretString:password::}}',
        ],
      ],
    },
    ServerlessV2ScalingConfiguration: {
      MaxCapacity: 10,
      MinCapacity: 0.5,
    },
    VpcSecurityGroupIds: [
      {
        'Fn::GetAtt': ['KeyCloakDatabaseDBClusterSecurityGroup843B4392', 'GroupId'],
      },
    ],
  });
  // we should have 2 db instances in the cluster
  t.resourceCountIs('AWS::RDS::DBInstance', 2);
  // we should have db instance with db.serverless instance class
  t.hasResourceProperties('AWS::RDS::DBInstance', {
    DBInstanceClass: 'db.serverless',
  });
  // we should have 2 secrets
  t.resourceCountIs('AWS::SecretsManager::Secret', 3);
  // we should have ecs service
  t.hasResourceProperties('AWS::ECS::Service', {
    Cluster: {
      Ref: 'KeyCloakKeyCloakContainerSerivceClusterA18E44FF',
    },
    DeploymentConfiguration: {
      MaximumPercent: 200,
      MinimumHealthyPercent: 50,
    },
    DesiredCount: 2,
    EnableECSManagedTags: false,
    HealthCheckGracePeriodSeconds: 120,
    LaunchType: 'FARGATE',
    LoadBalancers: [
      {
        ContainerName: 'keycloak',
        ContainerPort: 8080,
        TargetGroupArn: {
          Ref: 'KeyCloakKeyCloakContainerSerivceALBALBHttpsListenerECSTargetGroupA6169207',
        },
      },
    ],
    NetworkConfiguration: {
      AwsvpcConfiguration: {
        AssignPublicIp: 'DISABLED',
        SecurityGroups: [
          {
            'Fn::GetAtt': [
              'KeyCloakKeyCloakContainerSerivceServiceSecurityGroup4C80023D',
              'GroupId',
            ],
          },
        ],
        Subnets: [
          {
            Ref: 'KeyCloakVpcPrivateSubnet1SubnetA692DFFF',
          },
          {
            Ref: 'KeyCloakVpcPrivateSubnet2SubnetC8682D75',
          },
        ],
      },
    },
    TaskDefinition: {
      Ref: 'KeyCloakKeyCloakContainerSerivceTaskDef30C9533A',
    },
  });
});

test('with single rds instance', () => {
  // GIVEN
  const app = new App();
  const stack = new Stack(app, 'testing-stack');

  // WHEN
  new kc.KeyCloak(stack, 'KeyCloak', {
    certificateArn: 'MOCK_ARN',
    singleDbInstance: true,
    keycloakVersion: KeycloakVersion.V21_0_1,
  });

  // THEN
  const t = assertions.Template.fromStack(stack);
  // we should have no cluster
  t.resourceCountIs('AWS::RDS::DBCluster', 0);
  // we should have 1 db instance in the cluster
  t.resourceCountIs('AWS::RDS::DBInstance', 1);
  t.hasResourceProperties('AWS::RDS::DBInstance', {
    DBInstanceClass: 'db.r5.large',
    AllocatedStorage: '100',
    CopyTagsToSnapshot: true,
    DBParameterGroupName: 'default.mysql8.0',
    DBSubnetGroupName: {
      Ref: 'KeyCloakDatabaseDBInstanceSubnetGroup71BF616F',
    },
    Engine: 'mysql',
    EngineVersion: '8.0.21',
    MasterUsername: 'admin',
    MasterUserPassword: {
      'Fn::Join': [
        '',
        [
          '{{resolve:secretsmanager:',
          {
            Ref: 'testingstackKeyCloakDatabaseDBInstanceSecretA1C7CB093fdaad7efa858a3daf9490cf0a702aeb',
          },
          ':SecretString:password::}}',
        ],
      ],
    },
    StorageType: 'gp2',
    VPCSecurityGroups: [
      {
        'Fn::GetAtt': ['KeyCloakDatabaseDBInstanceSecurityGroupC897947D', 'GroupId'],
      },
    ],
  });
  // we should have 2 secrets
  t.resourceCountIs('AWS::SecretsManager::Secret', 3);
  // we should have ecs service
  t.hasResourceProperties('AWS::ECS::Service', {
    Cluster: {
      Ref: 'KeyCloakKeyCloakContainerSerivceClusterA18E44FF',
    },
    DeploymentConfiguration: {
      MaximumPercent: 200,
      MinimumHealthyPercent: 50,
    },
    DesiredCount: 2,
    EnableECSManagedTags: false,
    HealthCheckGracePeriodSeconds: 120,
    LaunchType: 'FARGATE',
    LoadBalancers: [
      {
        ContainerName: 'keycloak',
        ContainerPort: 8080,
        TargetGroupArn: {
          Ref: 'KeyCloakKeyCloakContainerSerivceALBALBHttpsListenerECSTargetGroupA6169207',
        },
      },
    ],
    NetworkConfiguration: {
      AwsvpcConfiguration: {
        AssignPublicIp: 'DISABLED',
        SecurityGroups: [
          {
            'Fn::GetAtt': [
              'KeyCloakKeyCloakContainerSerivceServiceSecurityGroup4C80023D',
              'GroupId',
            ],
          },
        ],
        Subnets: [
          {
            Ref: 'KeyCloakVpcPrivateSubnet1SubnetA692DFFF',
          },
          {
            Ref: 'KeyCloakVpcPrivateSubnet2SubnetC8682D75',
          },
        ],
      },
    },
    TaskDefinition: {
      Ref: 'KeyCloakKeyCloakContainerSerivceTaskDef30C9533A',
    },
  });
});

test('with env', () => {
  // GIVEN
  const app = new App();
  const stack = new Stack(app, 'testing-stack');

  // WHEN
  new kc.KeyCloak(stack, 'KeyCloak', {
    keycloakVersion: KeycloakVersion.V21_0_1,
    certificateArn: 'MOCK_ARN',
    env: {
      JAVA_OPTS: '-DHelloWorld',
    },
    hostname: 'keycloak.test',
  });

  // THEN
  const t = assertions.Template.fromStack(stack);

  t.hasResourceProperties('AWS::ECS::TaskDefinition', {
    ContainerDefinitions: [
      {
        Environment: [
          {
            Name: 'JAVA_OPTS_APPEND',
          },
          {
            Name: 'KC_CACHE_STACK',
            Value: 'ec2',
          },
          {
            Name: 'KC_DB',
            Value: 'mysql',
          },
          {
            Name: 'KC_DB_URL_DATABASE',
            Value: 'keycloak',
          },
          {
            Name: 'KC_DB_URL',
            Value: {
              'Fn::Join': [
                '',
                [
                  'jdbc:mysql://',
                  {
                    'Fn::GetAtt': [
                      'KeyCloakDatabaseDBCluster06E9C0E1',
                      'Endpoint.Address',
                    ],
                  },
                  ':3306/keycloak',
                ],
              ],
            },
          },
          {
            Name: 'KC_DB_URL_PORT',
            Value: '3306',
          },
          {
            Name: 'KC_DB_USERNAME',
            Value: 'admin',
          },
          {
            Name: 'KC_HOSTNAME',
            Value: 'keycloak.test',
          },
          {
            Name: 'KC_HOSTNAME_STRICT_BACKCHANNEL',
            Value: 'true',
          },
          {
            Name: 'KC_PROXY',
            Value: 'edge',
          },
          {
            Name: 'KC_HEALTH_ENABLED',
            Value: 'true',
          },
          {
            Name: 'JAVA_OPTS',
            Value: '-DHelloWorld',
          },
        ],
        Essential: true,
        Image: {
          'Fn::FindInMap': [
            'KeyCloakKeyCloakContainerSerivceKeycloakImageMapF79EAEA3',
            {
              Ref: 'AWS::Partition',
            },
            'uri',
          ],
        },
        LogConfiguration: {
          LogDriver: 'awslogs',
          Options: {
            'awslogs-group': {
              Ref: 'KeyCloakKeyCloakContainerSerivceLogGroup010F2AAE',
            },
            'awslogs-stream-prefix': 'keycloak',
            'awslogs-region': {
              Ref: 'AWS::Region',
            },
          },
        },
        Name: 'keycloak',
        PortMappings: [
          {
            ContainerPort: 8080,
            Protocol: 'tcp',
          },
          {
            ContainerPort: 7800,
            Protocol: 'tcp',
          },
          {
            ContainerPort: 57800,
            Protocol: 'tcp',
          },
        ],
        Secrets: [
          {
            Name: 'KC_DB_PASSWORD',
            ValueFrom: {
              'Fn::Join': [
                '',
                [
                  {
                    Ref: 'KeyCloakDatabaseDBClusterSecretAttachment50401C92',
                  },
                  ':password::',
                ],
              ],
            },
          },
          {
            Name: 'KEYCLOAK_ADMIN',
            ValueFrom: {
              'Fn::Join': [
                '',
                [
                  {
                    Ref: 'KeyCloakKCSecretF8498E5C',
                  },
                  ':username::',
                ],
              ],
            },
          },
          {
            Name: 'KEYCLOAK_ADMIN_PASSWORD',
            ValueFrom: {
              'Fn::Join': [
                '',
                [
                  {
                    Ref: 'KeyCloakKCSecretF8498E5C',
                  },
                  ':password::',
                ],
              ],
            },
          },
        ],
      },
    ],
    Cpu: '2048',
    ExecutionRoleArn: {
      'Fn::GetAtt': ['KeyCloakKeyCloakContainerSerivceTaskRole0658CED2', 'Arn'],
    },
    Family: 'testingstackKeyCloakKeyCloakContainerSerivceTaskDef799BAD5B',
    Memory: '4096',
    NetworkMode: 'awsvpc',
    RequiresCompatibilities: ['FARGATE'],
    TaskRoleArn: {
      'Fn::GetAtt': ['KeyCloakKeyCloakContainerSerivceTaskDefTaskRole0DC4D418', 'Arn'],
    },
  });
});
