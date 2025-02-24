import * as cdk from 'aws-cdk-lib';
import {
  aws_certificatemanager as certmgr,
  aws_ec2 as ec2,
  aws_ecs as ecs,
  aws_elasticloadbalancingv2 as elbv2,
  aws_iam as iam,
  aws_logs as logs,
  aws_rds as rds,
  aws_s3 as s3,
  aws_secretsmanager as secretsmanager,
  RemovalPolicy,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

// regional availibility for aurora serverless
// see https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Concepts.AuroraFeaturesRegionsDBEngines.grids.html
const AURORA_SERVERLESS_SUPPORTED_REGIONS = [
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2',
  'ap-south-1',
  'ap-northeast-1',
  'ap-northeast-2',
  'ap-southeast-1',
  'ap-southeast-2',
  'ca-central-1',
  'eu-central-1',
  'eu-west-1',
  'eu-west-2',
  'eu-west-3',
  'cn-northwest-1',
];

/**
 * Keycloak  version
 */
export class KeycloakVersion {
  /**
   * Keycloak version 12.0.4
   */
  public static readonly V12_0_4 = KeycloakVersion.of('12.0.4');

  /**
   * Keycloak version 15.0.0
   */
  public static readonly V15_0_0 = KeycloakVersion.of('15.0.0');

  /**
   * Keycloak version 15.0.1
   */
  public static readonly V15_0_1 = KeycloakVersion.of('15.0.1');

  /**
   * Keycloak version 15.0.2
   */
  public static readonly V15_0_2 = KeycloakVersion.of('15.0.2');

  /**
   * Keycloak version 16.1.1
   */
  public static readonly V16_1_1 = KeycloakVersion.of('16.1.1');

  /**
   * Keycloak version 17.0.1
   */
  public static readonly V17_0_1 = KeycloakVersion.of('17.0.1');

  /**
   * Keycloak version 18.0.2
   */
  public static readonly V18_0_3 = KeycloakVersion.of('18.0.2');

  /**
   * Keycloak version 19.0.3
   */
  public static readonly V19_0_3 = KeycloakVersion.of('19.0.3');

  /**
   * Keycloak version 20.0.5
   */
  public static readonly V20_0_3 = KeycloakVersion.of('20.0.5');

  /**
   * Keycloak version 21.0.0
   */
  public static readonly V21_0_0 = KeycloakVersion.of('21.0.0');

  /**
   * Keycloak version 21.0.1
   */
  public static readonly V21_0_1 = KeycloakVersion.of('21.0.1');

  /**
   * Custom cluster version
   * @param version custom version number
   */
  public static of(version: string) { return new KeycloakVersion(version); }
  /**
   *
   * @param version cluster version number
   */
  private constructor(public readonly version: string) { }
}

interface dockerImageMap {
  'aws': string;
  'aws-cn': string;
}

const KEYCLOAK_DOCKER_IMAGE_URI_MAP: dockerImageMap = {
  'aws': 'quay.io/keycloak/keycloak:',
  'aws-cn': '048912060910.dkr.ecr.cn-northwest-1.amazonaws.com.cn/dockerhub/jboss/keycloak:',
};

/**
 * The ECS task autoscaling definition
 */
export interface AutoScaleTask {
  /**
   * The minimal count of the task number
   *
   * @default - nodeCount
   */
  readonly min?: number;
  /**
   * The maximal count of the task number
   *
   * @default - min + 5
   */
  readonly max?: number;
  /**
   * The target cpu utilization for the service autoscaling
   *
   * @default 75
   */
  readonly targetCpuUtilization?: number;
}

export interface KeyCloakProps {
  /**
   * The Keycloak version for the cluster.
   */
  readonly keycloakVersion: KeycloakVersion;
  /**
   * The environment variables to pass to the keycloak container
   */
  readonly env?: { [key: string]: string };
  /**
   * VPC for the workload
   */
  readonly vpc?: ec2.IVpc;
  /**
   * ACM certificate ARN to import
   */
  readonly certificateArn: string;
  /**
   * Create a bastion host for debugging or trouble-shooting
   *
   * @default false
   */
  readonly bastion?: boolean;
  /**
   * Number of keycloak node in the cluster
   *
   * @default 2
   */
  readonly nodeCount?: number;
  /**
   * VPC public subnets for ALB
   *
   * @default - VPC public subnets
   */
  readonly publicSubnets?: ec2.SubnetSelection;
  /**
   * VPC private subnets for keycloak service
   *
   * @default - VPC private subnets
   */
  readonly privateSubnets?: ec2.SubnetSelection;
  /**
   * VPC subnets for database
   *
   * @default - VPC isolated subnets
   */
  readonly databaseSubnets?: ec2.SubnetSelection;
  /**
   * Database instance type
   *
   * @default r5.large
   */
  readonly databaseInstanceType?: ec2.InstanceType;
  /**
   * The database instance engine
   *
   * @default - MySQL 8.0.21
   */
  readonly instanceEngine?: rds.IInstanceEngine;
  /**
   * The database cluster engine
   *
   * @default rds.AuroraMysqlEngineVersion.VER_2_09_1
   */
  readonly clusterEngine?: rds.IClusterEngine;
  /**
   * Whether to use aurora serverless. When enabled, the `databaseInstanceType` and
   * `engine` will be ignored. The `rds.DatabaseClusterEngine.AURORA_MYSQL` will be used as
   * the default cluster engine instead.
   *
   * @default false
   */
  readonly auroraServerless?: boolean;
  /**
   * Whether to use aurora serverless v2. When enabled, the `databaseInstanceType` will be ignored.
   *
   * @default false
   */
  readonly auroraServerlessV2?: boolean;
  /**
   * Whether to use single RDS instance rather than RDS cluster. Not recommended for production.
   *
   * @default false
   */
  readonly singleDbInstance?: boolean;
  /**
   * database backup retension
   *
   * @default - 7 days
   */
  readonly backupRetention?: cdk.Duration;
  /**
   * The sticky session duration for the keycloak workload with ALB.
   *
   * @default - one day
   */
  readonly stickinessCookieDuration?: cdk.Duration;
  /**
   * Autoscaling for the ECS Service
   *
   * @default - no ecs service autoscaling
   */
  readonly autoScaleTask?: AutoScaleTask;

  /**
   * Whether to put the load balancer in the public or private subnets
   *
   * @default true
   */
  readonly internetFacing?: boolean;

  /**
   * The hostname to use for the keycloak server
   */
  readonly hostname?: string;

  /**
   * The minimum number of Aurora Serverless V2 capacity units.
   *
   * @default 0.5
  */
  readonly databaseMinCapacity?: number;

  /**
  * The maximum number of Aurora Serverless V2 capacity units.
  *
   * @default 10
   */
  readonly databaseMaxCapacity?: number;

  /**
   * Controls what happens to the database if it stops being managed by CloudFormation
   *
   * @default RemovalPolicy.RETAIN
   */
  readonly databaseRemovalPolicy?: cdk.RemovalPolicy;


  /**
   * Overrides the default image
   *
   * @default quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
   */
  readonly containerImage?: ecs.ContainerImage;

  /**
   * The number of cpu units used by the Keycloak task.
   * You must use one of the following values, which determines your range of valid values for the memory parameter:
   * 256 (.25 vCPU) - Available memory values: 512 (0.5 GB), 1024 (1 GB), 2048 (2 GB)
   * 512 (.5 vCPU) - Available memory values: 1024 (1 GB), 2048 (2 GB), 3072 (3 GB), 4096 (4 GB)
   * 1024 (1 vCPU) - Available memory values: 2048 (2 GB), 3072 (3 GB), 4096 (4 GB), 5120 (5 GB), 6144 (6 GB), 7168 (7 GB), 8192 (8 GB)
   * 2048 (2 vCPU) - Available memory values: Between 4096 (4 GB) and 16384 (16 GB) in increments of 1024 (1 GB)
   * 4096 (4 vCPU) - Available memory values: Between 8192 (8 GB) and 30720 (30 GB) in increments of 1024 (1 GB)
   * 8192 (8 vCPU) - Available memory values: Between 16384 (16 GB) and 61440 (60 GB) in increments of 4096 (4 GB)
   * 16384 (16 vCPU) - Available memory values: Between 32768 (32 GB) and 122880 (120 GB) in increments of 8192 (8 GB)
   *
   * @default 2048
   */
  readonly cpu?: number;

  /**
   * The amount (in MiB) of memory used by the task.
   * You must use one of the following values, which determines your range of valid values for the cpu parameter:
   * 512 (0.5 GB), 1024 (1 GB), 2048 (2 GB) - Available cpu values: 256 (.25 vCPU)
   * 1024 (1 GB), 2048 (2 GB), 3072 (3 GB), 4096 (4 GB) - Available cpu values: 512 (.5 vCPU)
   * 2048 (2 GB), 3072 (3 GB), 4096 (4 GB), 5120 (5 GB), 6144 (6 GB), 7168 (7 GB), 8192 (8 GB) - Available cpu values: 1024 (1 vCPU)
   * Between 4096 (4 GB) and 16384 (16 GB) in increments of 1024 (1 GB) - Available cpu values: 2048 (2 vCPU)
   * Between 8192 (8 GB) and 30720 (30 GB) in increments of 1024 (1 GB) - Available cpu values: 4096 (4 vCPU)
   * Between 16384 (16 GB) and 61440 (60 GB) in increments of 4096 (4 GB) - Available cpu values: 8192 (8 vCPU)
   * Between 32768 (32 GB) and 122880 (120 GB) in increments of 8192 (8 GB) - Available cpu values: 16384 (16 vCPU)
   *
   * @default 4096
   */
  readonly memoryLimitMiB?: number;

  /**
   * Number of instances to spawn in the database cluster (for cluster database options only).
   * Has to be at least 1.
   *
   * @default 2
   */
  readonly dbClusterInstances?: number;

  /**
   * Healthcheck URL for the Target Group to evaluate the state of the task.
   * HTTP 200 response is expected.
   */
  readonly healthCheckPath?: string;
}

export class KeyCloak extends Construct {
  readonly vpc: ec2.IVpc;
  readonly db?: Database;
  readonly applicationLoadBalancer: elbv2.ApplicationLoadBalancer;
  // readonly networkLoadBalancer: elbv2.NetworkLoadBalancer;
  readonly keycloakSecret: secretsmanager.ISecret;
  constructor(scope: Construct, id: string, props: KeyCloakProps) {
    super(scope, id);

    const region = cdk.Stack.of(this).region;
    const regionIsResolved = !cdk.Token.isUnresolved(region);
    const { cpu = 2048, memoryLimitMiB =4096, dbClusterInstances = 2, healthCheckPath } = props;

    if (props.auroraServerless && regionIsResolved && !AURORA_SERVERLESS_SUPPORTED_REGIONS.includes(region)) {
      throw new Error(`Aurora serverless is not supported in ${region}`);
    }

    this.keycloakSecret = this._generateKeycloakSecret();
    this.vpc = props.vpc ?? getOrCreateVpc(this);

    this.db = this.addDatabase({
      vpc: this.vpc,
      databaseSubnets: props.databaseSubnets,
      instanceType: props.databaseInstanceType,
      instanceEngine: props.instanceEngine,
      clusterEngine: props.clusterEngine,
      auroraServerless: false,
      auroraServerlessV2: false,
      singleDbInstance: props.singleDbInstance,
      backupRetention: props.backupRetention,
      maxCapacity: props.databaseMaxCapacity,
      minCapacity: props.databaseMinCapacity,
      removalPolicy: props.databaseRemovalPolicy,
      dbClusterInstances: dbClusterInstances,
    });
    const keycloakContainerService = this.addKeyCloakContainerService({
      database: this.db,
      vpc: this.vpc,
      keycloakVersion: props.keycloakVersion,
      publicSubnets: props.publicSubnets,
      privateSubnets: props.privateSubnets,
      keycloakSecret: this.keycloakSecret,
      certificate: certmgr.Certificate.fromCertificateArn(this, 'ACMCert', props.certificateArn),
      bastion: props.bastion,
      nodeCount: props.nodeCount,
      stickinessCookieDuration: props.stickinessCookieDuration,
      autoScaleTask: props.autoScaleTask,
      env: props.env,
      internetFacing: props.internetFacing ?? true,
      hostname: props.hostname,
      containerImage: props.containerImage,
      cpu,
      memoryLimitMiB,
      healthCheckPath,
    });

    this.applicationLoadBalancer = keycloakContainerService.applicationLoadBalancer;
    // this.networkLoadBalancer = keycloakContainerService.networkLoadBalancer;
    if (!cdk.Stack.of(this).templateOptions.description) {
      cdk.Stack.of(this).templateOptions.description = '(SO8021) - Deploy keycloak on AWS with cdk-keycloak construct library';
    }
  }
  public addDatabase(props: DatabaseProps): Database {
    return new Database(this, 'Database', props);
  }
  public addKeyCloakContainerService(props: ContainerServiceProps) {
    return new ContainerService(this, 'KeyCloakContainerSerivce', props);
  }
  private _generateKeycloakSecret(): secretsmanager.ISecret {
    return new secretsmanager.Secret(this, 'KCSecret', {
      generateSecretString: {
        generateStringKey: 'password',
        excludePunctuation: true,
        passwordLength: 12,
        secretStringTemplate: JSON.stringify({ username: 'keycloak' }),
      },
    });
  }
}

export interface DatabaseProps {
  /**
   * The VPC for the database
   */
  readonly vpc: ec2.IVpc;
  /**
   * VPC subnets for database
   */
  readonly databaseSubnets?: ec2.SubnetSelection;
  /**
   * The database instance type
   *
   * @default r5.large
   */
  readonly instanceType?: ec2.InstanceType;
  /**
   * The database instance engine
   *
   * @default - MySQL 8.0.21
   */
  readonly instanceEngine?: rds.IInstanceEngine;
  /**
   * The database cluster engine
   *
   * @default rds.AuroraMysqlEngineVersion.VER_2_09_1
   */
  readonly clusterEngine?: rds.IClusterEngine;
  /**
   * enable aurora serverless
   *
   * @default false
   */
  readonly auroraServerless?: boolean;
  /**
   * enable aurora serverless v2
   *
   * @default false
   */
  readonly auroraServerlessV2?: boolean;

  /**
   * Whether to use single RDS instance rather than RDS cluster. Not recommended for production.
   *
   * @default false
   */
  readonly singleDbInstance?: boolean;
  /**
   * database backup retension
   *
   * @default - 7 days
   */
  readonly backupRetention?: cdk.Duration;
  /**
   * The minimum number of Aurora Serverless V2 capacity units.
   *
   * @default 0.5
  */
  readonly minCapacity?: number;
  /**
   * The maximum number of Aurora Serverless V2 capacity units.
   *
   * @default 10
   */
  readonly maxCapacity?: number;

  /**
   * Controls what happens to the database if it stops being managed by CloudFormation
   *
   * @default RemovalPolicy.RETAIN
   */
  readonly removalPolicy?: cdk.RemovalPolicy;

  /**
   * Number of instances to spawn in the database cluster (for cluster database options only).
   *
   * @default 2
   */
  readonly dbClusterInstances?: number;
}

/**
 * Database configuration
 */
export interface DatabaseConfig {
  /**
   * The database secret.
   */
  readonly secret: secretsmanager.ISecret;
  /**
   * The database connnections.
   */
  readonly connections: ec2.Connections;
  /**
   * The endpoint address for the database.
   */
  readonly endpoint: string;
  /**
   * The databasae identifier.
   */
  readonly identifier: string;
}

/**
 * Represents the database instance or database cluster
 */
export class Database extends Construct {
  readonly vpc: ec2.IVpc;
  readonly clusterEndpointHostname: string;
  readonly clusterIdentifier: string;
  readonly secret: secretsmanager.ISecret;
  readonly connections: ec2.Connections;
  private readonly _mysqlListenerPort: number = 3306;

  constructor(scope: Construct, id: string, props: DatabaseProps) {
    super(scope, id);
    this.vpc = props.vpc;
    let config;
    if (props.auroraServerless) {
      config = this._createServerlessCluster(props);
    } else if (props.auroraServerlessV2) {
      config = this._createServerlessV2Cluster(props);
    } else if (props.singleDbInstance) {
      config = this._createRdsInstance(props);
    } else {
      config = this._createRdsCluster(props);
    }
    this.secret = config.secret;
    // allow internally from the same security group
    config.connections.allowInternally(ec2.Port.tcp(this._mysqlListenerPort));
    // allow from the whole vpc cidr
    config.connections.allowFrom(ec2.Peer.ipv4(props.vpc.vpcCidrBlock), ec2.Port.tcp(this._mysqlListenerPort));
    this.clusterEndpointHostname = config.endpoint;
    this.clusterIdentifier = config.identifier;
    this.connections = config.connections;
    printOutput(this, 'DBSecretArn', config.secret.secretArn);
    printOutput(this, 'clusterEndpointHostname', this.clusterEndpointHostname);
    printOutput(this, 'clusterIdentifier', this.clusterIdentifier);
  }
  private _createRdsInstance(props: DatabaseProps): DatabaseConfig {
    const dbInstance = new rds.DatabaseInstance(this, 'DBInstance', {
      vpc: props.vpc,
      databaseName: 'keycloak',
      vpcSubnets: props.databaseSubnets,
      engine: props.instanceEngine ?? rds.DatabaseInstanceEngine.mysql({
        version: rds.MysqlEngineVersion.VER_8_0_21,
      }),
      storageEncrypted: true,
      backupRetention: props.backupRetention ?? cdk.Duration.days(7),
      credentials: rds.Credentials.fromGeneratedSecret('admin'),
      instanceType: props.instanceType ?? new ec2.InstanceType('r5.large'),
      parameterGroup: rds.ParameterGroup.fromParameterGroupName(this, 'ParameterGroup', 'default.mysql8.0'),
      deletionProtection: false,
      removalPolicy: props.removalPolicy ?? cdk.RemovalPolicy.RETAIN,
    });
    return {
      connections: dbInstance.connections,
      endpoint: dbInstance.dbInstanceEndpointAddress,
      identifier: dbInstance.instanceIdentifier,
      secret: dbInstance.secret!,
    };
  }
  // create a RDS for MySQL DB cluster
  private _createRdsCluster(props: DatabaseProps): DatabaseConfig {
    const dbCluster = new rds.DatabaseCluster(this, 'DBCluster', {
      engine: props.clusterEngine ?? rds.DatabaseClusterEngine.auroraMysql({
        version: rds.AuroraMysqlEngineVersion.VER_2_09_1,
      }),
      instances: props.dbClusterInstances ?? 2,
      defaultDatabaseName: 'keycloak',
      deletionProtection: false,
      credentials: rds.Credentials.fromGeneratedSecret('admin'),
      instanceProps: {
        vpc: props.vpc,
        vpcSubnets: props.databaseSubnets,
        instanceType: props.instanceType ?? new ec2.InstanceType('r5.large'),
      },
      parameterGroup: rds.ParameterGroup.fromParameterGroupName(this, 'ParameterGroup', 'default.aurora-mysql8.0'),
      backup: {
        retention: props.backupRetention ?? cdk.Duration.days(7),
      },
      storageEncrypted: true,
      removalPolicy: props.removalPolicy ?? cdk.RemovalPolicy.RETAIN,
    });
    return {
      connections: dbCluster.connections,
      endpoint: dbCluster.clusterEndpoint.hostname,
      identifier: dbCluster.clusterIdentifier,
      secret: dbCluster.secret!,
    };
  }
  private _createServerlessCluster(props: DatabaseProps): DatabaseConfig {
    const dbCluster = new rds.ServerlessCluster(this, 'AuroraServerlessCluster', {
      engine: rds.DatabaseClusterEngine.AURORA_MYSQL,
      vpc: props.vpc,
      defaultDatabaseName: 'keycloak',
      vpcSubnets: props.databaseSubnets,
      credentials: rds.Credentials.fromGeneratedSecret('admin'),
      backupRetention: props.backupRetention ?? cdk.Duration.days(7),
      deletionProtection: false,
      removalPolicy: props.removalPolicy ?? cdk.RemovalPolicy.RETAIN,
      parameterGroup: rds.ParameterGroup.fromParameterGroupName(this, 'ParameterGroup', 'default.aurora-mysql8.0'),
    });
    return {
      connections: dbCluster.connections,
      endpoint: dbCluster.clusterEndpoint.hostname,
      identifier: dbCluster.clusterIdentifier,
      secret: dbCluster.secret!,
    };
  }
  // create a RDS for MySQL DB cluster with Aurora Serverless v2
  private _createServerlessV2Cluster(props: DatabaseProps): DatabaseConfig {
    const dbCluster = new rds.DatabaseCluster(this, 'DBCluster', {
      engine: props.clusterEngine ?? rds.DatabaseClusterEngine.auroraMysql({
        version: rds.AuroraMysqlEngineVersion.VER_3_02_0,
      }),
      instances: props.dbClusterInstances ?? 2,
      defaultDatabaseName: 'keycloak',
      deletionProtection: false,
      credentials: rds.Credentials.fromGeneratedSecret('admin'),
      instanceProps: {
        vpc: props.vpc,
        vpcSubnets: props.databaseSubnets,
        // Specify serverless Instance Type
        instanceType: new ec2.InstanceType('serverless'),
      },
      // Set default parameter group for Aurora MySQL 8.0
      parameterGroup: rds.ParameterGroup.fromParameterGroupName(this, 'ParameterGroup', 'default.aurora-mysql8.0'),
      backup: {
        retention: props.backupRetention ?? cdk.Duration.days(7),
      },
      storageEncrypted: true,
      removalPolicy: props.removalPolicy ?? cdk.RemovalPolicy.RETAIN,
    });
    // Set Serverless V2 Scaling Configuration
    // TODO: Use cleaner way to set scaling configuration.
    // https://github.com/aws/aws-cdk/issues/20197
    (
      dbCluster.node.findChild('Resource') as rds.CfnDBCluster
    ).serverlessV2ScalingConfiguration = {
      minCapacity: props.minCapacity ?? 0.5,
      maxCapacity: props.maxCapacity ?? 10,
    };
    return {
      connections: dbCluster.connections,
      endpoint: dbCluster.clusterEndpoint.hostname,
      identifier: dbCluster.clusterIdentifier,
      secret: dbCluster.secret!,
    };
  }
}

export interface ContainerServiceProps {
  /**
   * The environment variables to pass to the keycloak container
   */
  readonly env?: { [key: string]: string };
  /**
   * Keycloak version for the container image
   */
  readonly keycloakVersion: KeycloakVersion;
  /**
   * The VPC for the service
   */
  readonly vpc: ec2.IVpc;
  /**
   * VPC subnets for keycloak service
   */
  readonly privateSubnets?: ec2.SubnetSelection;
  /**
   * VPC public subnets for ALB
   */
  readonly publicSubnets?: ec2.SubnetSelection;
  /**
   * The RDS database for the service
   */
  readonly database: Database;
  /**
   * The secrets manager secret for the keycloak
   */
  readonly keycloakSecret: secretsmanager.ISecret;
  /**
   * The ACM certificate
   */
  readonly certificate: certmgr.ICertificate;
  /**
   * Whether to create the bastion host
   * @default false
   */
  readonly bastion?: boolean;
  /**
   * Whether to enable the ECS service deployment circuit breaker
   * @default false
   */
  readonly circuitBreaker?: boolean;
  /**
   * Number of keycloak node in the cluster
   *
   * @default 1
   */
  readonly nodeCount?: number;
  /**
   * The sticky session duration for the keycloak workload with ALB.
   *
   * @default - one day
   */
  readonly stickinessCookieDuration?: cdk.Duration;

  /**
   * Autoscaling for the ECS Service
   *
   * @default - no ecs service autoscaling
   */
  readonly autoScaleTask?: AutoScaleTask;

  /**
   * Whether to put the put the load balancer in the public or private subnets
   *
   * @default true
   */
  readonly internetFacing?: boolean;

  /**
   * The hostname to use for the keycloak server
   */
  readonly hostname?: string;


  /**
   * Overrides the default image
   *
   * @default quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
   */
  readonly containerImage?: ecs.ContainerImage;

  /**
   * The number of cpu units used by the Keycloak task.
   * You must use one of the following values, which determines your range of valid values for the memory parameter:
   * 256 (.25 vCPU) - Available memory values: 512 (0.5 GB), 1024 (1 GB), 2048 (2 GB)
   * 512 (.5 vCPU) - Available memory values: 1024 (1 GB), 2048 (2 GB), 3072 (3 GB), 4096 (4 GB)
   * 1024 (1 vCPU) - Available memory values: 2048 (2 GB), 3072 (3 GB), 4096 (4 GB), 5120 (5 GB), 6144 (6 GB), 7168 (7 GB), 8192 (8 GB)
   * 2048 (2 vCPU) - Available memory values: Between 4096 (4 GB) and 16384 (16 GB) in increments of 1024 (1 GB)
   * 4096 (4 vCPU) - Available memory values: Between 8192 (8 GB) and 30720 (30 GB) in increments of 1024 (1 GB)
   * 8192 (8 vCPU) - Available memory values: Between 16384 (16 GB) and 61440 (60 GB) in increments of 4096 (4 GB)
   * 16384 (16 vCPU) - Available memory values: Between 32768 (32 GB) and 122880 (120 GB) in increments of 8192 (8 GB)
   */
  readonly cpu: number;

  /**
   * The amount (in MiB) of memory used by the task.
   * You must use one of the following values, which determines your range of valid values for the cpu parameter:
   * 512 (0.5 GB), 1024 (1 GB), 2048 (2 GB) - Available cpu values: 256 (.25 vCPU)
   * 1024 (1 GB), 2048 (2 GB), 3072 (3 GB), 4096 (4 GB) - Available cpu values: 512 (.5 vCPU)
   * 2048 (2 GB), 3072 (3 GB), 4096 (4 GB), 5120 (5 GB), 6144 (6 GB), 7168 (7 GB), 8192 (8 GB) - Available cpu values: 1024 (1 vCPU)
   * Between 4096 (4 GB) and 16384 (16 GB) in increments of 1024 (1 GB) - Available cpu values: 2048 (2 vCPU)
   * Between 8192 (8 GB) and 30720 (30 GB) in increments of 1024 (1 GB) - Available cpu values: 4096 (4 vCPU)
   * Between 16384 (16 GB) and 61440 (60 GB) in increments of 4096 (4 GB) - Available cpu values: 8192 (8 vCPU)
   * Between 32768 (32 GB) and 122880 (120 GB) in increments of 8192 (8 GB) - Available cpu values: 16384 (16 vCPU)
   */
  readonly memoryLimitMiB: number;

  /**
   * Healthcheck URL for the Target Group to evaluate the state of the task.
   * HTTP 200 response is expected.
   *
   * @default /
   */
  readonly healthCheckPath?: string;
}

export class ContainerService extends Construct {
  readonly service: ecs.FargateService;
  readonly applicationLoadBalancer: elbv2.ApplicationLoadBalancer;
  // readonly networkLoadBalancer: elbv2.NetworkLoadBalancer;
  readonly keycloakUserSecret: secretsmanager.ISecret;
  constructor(scope: Construct, id: string, props: ContainerServiceProps) {
    super(scope, id);

    const { cpu, memoryLimitMiB, healthCheckPath = '/' } = props;

    const region = cdk.Stack.of(this).region;
    const containerPort = 8080;
    const connectionString = `jdbc:mysql://${props.database.clusterEndpointHostname}:3306/keycloak`;
    // const protocol = elbv2.ApplicationProtocol.HTTP;
    const entryPoint = ['/opt/keycloak/bin/kc.sh', 'start', '--optimized'];
    const s3PingBucket = new s3.Bucket(this, 'keycloak_s3_ping', { removalPolicy: RemovalPolicy.DESTROY });
    const image = props.containerImage ?? ecs.ContainerImage.fromRegistry(this.getKeyCloakDockerImageUri(props.keycloakVersion.version));
    const secrets: {[key: string]: cdk.aws_ecs.Secret} = {
      KC_DB_PASSWORD: ecs.Secret.fromSecretsManager(props.database.secret, 'password'),
      KEYCLOAK_ADMIN: ecs.Secret.fromSecretsManager(props.keycloakSecret, 'username'),
      KEYCLOAK_ADMIN_PASSWORD: ecs.Secret.fromSecretsManager(props.keycloakSecret, 'password'),
    };
    const portMappings: ecs.PortMapping[] = [
      { containerPort: containerPort }, // web port
      { containerPort: 7800 }, // jgroups-s3
      { containerPort: 57800 }, // jgroups-s3-fd
    ];
    const vpc = props.vpc;
    const cluster = new ecs.Cluster(this, 'Cluster', { vpc, containerInsights: true });
    cluster.node.addDependency(props.database);
    const executionRole = new iam.Role(this, 'TaskRole', {
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('ecs.amazonaws.com'),
        new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      ),
    });
    const taskDefinition = new ecs.FargateTaskDefinition(this, 'TaskDef', {
      cpu,
      memoryLimitMiB,
      executionRole,
    });

    const logGroup = new logs.LogGroup(this, 'LogGroup', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const s3User = new iam.User(this, 'S3KeycloakUser');
    const accessKey = new iam.AccessKey(this, 'S3KeycloakUserAccessKey', { user: s3User });
    this.keycloakUserSecret = new secretsmanager.Secret(this, 'S3KeycloakUserSecret', {
      secretStringValue: accessKey.secretAccessKey,
    });
    s3PingBucket!.grantReadWrite(s3User);

    const environment: {[key: string]: string} = {
      JAVA_OPTS_APPEND: `
      -Djgroups.s3.region_name=${region}
      -Djgroups.s3.bucket_name=${s3PingBucket!.bucketName}
      -Djgroups.s3.access_key=${accessKey.accessKeyId}
      -Djgroups.s3.secret_access_key=${accessKey.secretAccessKey}
      `.replace('\r\n', '').replace('\n', '').replace(/\s+/g, ' '),
      // We have selected the cache stack of 'ec2' which uses S3_PING under the hood
      // This is the AWS native cluster discovery approach for caching
      // See: https://www.keycloak.org/server/caching#_transport_stacks
      KC_CACHE_STACK: 'ec2',
      KC_DB: 'mysql',
      KC_DB_URL_DATABASE: 'keycloak',
      KC_DB_URL: connectionString,
      KC_DB_URL_PORT: '3306',
      KC_DB_USERNAME: 'admin',
      KC_HOSTNAME: props.hostname!,
      KC_HOSTNAME_STRICT_BACKCHANNEL: 'true',
      KC_PROXY: 'edge',
      KC_HEALTH_ENABLED: 'true',
    };

    const kc = taskDefinition.addContainer('keycloak', {
      image,
      entryPoint,
      environment: Object.assign(environment, props.env),
      secrets,
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'keycloak',
        logGroup,
      }),
    });
    kc.addPortMappings(...portMappings);

    // we need extra privileges to fetch keycloak docker images from China mirror site
    taskDefinition.executionRole?.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEC2ContainerRegistryReadOnly'));

    this.service = new ecs.FargateService(this, 'Service', {
      cluster,
      taskDefinition,
      circuitBreaker: props.circuitBreaker ? { rollback: true } : undefined,
      desiredCount: props.nodeCount ?? 2,
      healthCheckGracePeriod: cdk.Duration.seconds(120),
    });

    this.service.connections.allowFrom(this.service.connections, ec2.Port.tcp(7800), 'kc jgroups-tcp');
    this.service.connections.allowFrom(this.service.connections, ec2.Port.tcp(57800), 'kc jgroups-tcp-fd');
    s3PingBucket!.grantReadWrite(taskDefinition.taskRole);

    if (props.autoScaleTask) {
      const minCapacity = props.autoScaleTask.min ?? props.nodeCount ?? 2;
      const scaling = this.service.autoScaleTaskCount({
        minCapacity,
        maxCapacity: props.autoScaleTask.max ?? minCapacity + 5,
      });
      scaling.scaleOnCpuUtilization('CpuScaling', {
        targetUtilizationPercent: props.autoScaleTask.targetCpuUtilization ?? 75,
      });
    };

    // listener protocol 'TLS' is not supported with a target group with the target-type 'ALB'

    this.applicationLoadBalancer = new elbv2.ApplicationLoadBalancer(this, 'ALB', {
      vpc,
      vpcSubnets: props.publicSubnets,
      internetFacing: true,
      // vpcSubnets: props.internetFacing ? props.publicSubnets : props.privateSubnets,
      // internetFacing: props.internetFacing,
    });
    printOutput(this, 'EndpointURL', `https://${this.applicationLoadBalancer.loadBalancerDnsName}`);

    const listener = this.applicationLoadBalancer.addListener('ALB_HttpsListener', {
      protocol: elbv2.ApplicationProtocol.HTTPS,
      certificates: [{ certificateArn: props.certificate.certificateArn }],
    });
    // "If the target type is ALB, the target must have at least one listener that matches the target group port or any specified port overrides
    listener.addTargets('ECSTarget', {
      protocol: elbv2.ApplicationProtocol.HTTP,
      slowStart: cdk.Duration.seconds(60),
      stickinessCookieDuration: props.stickinessCookieDuration ?? cdk.Duration.days(1),
      targets: [this.service],
      healthCheck: {
        healthyThresholdCount: 3,
        path: healthCheckPath,
      },
    });

    // allow task execution role to read the secrets
    props.database.secret.grantRead(taskDefinition.executionRole!);
    props.keycloakSecret.grantRead(taskDefinition.executionRole!);

    // allow ecs task connect to database
    props.database.connections.allowDefaultPortFrom(this.service);


    // create a bastion host
    if (props.bastion === true) {
      const bast = new ec2.BastionHostLinux(this, 'Bast', {
        vpc,
        instanceType: new ec2.InstanceType('t3.small'),
      });
      props.database.connections.allowDefaultPortFrom(bast);
    }
  }
  private getImageUriFromMap(map: dockerImageMap, version: string, id: string): string {
    const stack = cdk.Stack.of(this);
    if (cdk.Token.isUnresolved(stack.region)) {
      const mapping: { [k1: string]: { [k2: string]: any } } = {};
      for (let [partition, uri] of Object.entries(map)) {
        uri += version;
        mapping[partition] = { uri };
      }
      const imageMap = new cdk.CfnMapping(this, id, { mapping });
      return imageMap.findInMap(cdk.Aws.PARTITION, 'uri');
    } else {
      if (stack.region.startsWith('cn-')) {
        return map['aws-cn'] += version;
      } else {
        return map.aws += version;
      }
    }
  }
  private getKeyCloakDockerImageUri(version: string): string {
    return this.getImageUriFromMap(KEYCLOAK_DOCKER_IMAGE_URI_MAP, version, 'KeycloakImageMap');
  }
}

/**
 * Create or import VPC
 * @param scope the cdk scope
 */
function getOrCreateVpc(scope: Construct): ec2.IVpc {
  // use an existing vpc or create a new one
  return scope.node.tryGetContext('use_default_vpc') === '1' ?
    ec2.Vpc.fromLookup(scope, 'Vpc', { isDefault: true }) :
    scope.node.tryGetContext('use_vpc_id') ?
      ec2.Vpc.fromLookup(scope, 'Vpc', { vpcId: scope.node.tryGetContext('use_vpc_id') }) :
      new ec2.Vpc(scope, 'Vpc', { maxAzs: 3, natGateways: 1 });
}

function printOutput(scope: Construct, id: string, key: string | number) {
  new cdk.CfnOutput(scope, id, { value: String(key) });
}
