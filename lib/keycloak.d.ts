import * as cdk from 'aws-cdk-lib';
import { aws_certificatemanager as certmgr, aws_ec2 as ec2, aws_ecs as ecs, aws_elasticloadbalancingv2 as elbv2, aws_rds as rds, aws_secretsmanager as secretsmanager } from 'aws-cdk-lib';
import { Construct } from 'constructs';
/**
 * Keycloak  version
 */
export declare class KeycloakVersion {
    readonly version: string;
    /**
     * Keycloak version 12.0.4
     */
    static readonly V12_0_4: KeycloakVersion;
    /**
     * Keycloak version 15.0.0
     */
    static readonly V15_0_0: KeycloakVersion;
    /**
     * Keycloak version 15.0.1
     */
    static readonly V15_0_1: KeycloakVersion;
    /**
     * Keycloak version 15.0.2
     */
    static readonly V15_0_2: KeycloakVersion;
    /**
     * Keycloak version 16.1.1
     */
    static readonly V16_1_1: KeycloakVersion;
    /**
     * Keycloak version 17.0.1
     */
    static readonly V17_0_1: KeycloakVersion;
    /**
     * Keycloak version 18.0.2
     */
    static readonly V18_0_3: KeycloakVersion;
    /**
     * Keycloak version 19.0.3
     */
    static readonly V19_0_3: KeycloakVersion;
    /**
     * Keycloak version 20.0.5
     */
    static readonly V20_0_3: KeycloakVersion;
    /**
     * Keycloak version 21.0.0
     */
    static readonly V21_0_0: KeycloakVersion;
    /**
     * Keycloak version 21.0.1
     */
    static readonly V21_0_1: KeycloakVersion;
    /**
     * Custom cluster version
     * @param version custom version number
     */
    static of(version: string): KeycloakVersion;
    /**
     *
     * @param version cluster version number
     */
    private constructor();
}
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
    readonly env?: {
        [key: string]: string;
    };
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
}
export declare class KeyCloak extends Construct {
    readonly vpc: ec2.IVpc;
    readonly db?: Database;
    readonly applicationLoadBalancer: elbv2.ApplicationLoadBalancer;
    readonly keycloakSecret: secretsmanager.ISecret;
    constructor(scope: Construct, id: string, props: KeyCloakProps);
    addDatabase(props: DatabaseProps): Database;
    addKeyCloakContainerService(props: ContainerServiceProps): ContainerService;
    private _generateKeycloakSecret;
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
export declare class Database extends Construct {
    readonly vpc: ec2.IVpc;
    readonly clusterEndpointHostname: string;
    readonly clusterIdentifier: string;
    readonly secret: secretsmanager.ISecret;
    readonly connections: ec2.Connections;
    private readonly _mysqlListenerPort;
    constructor(scope: Construct, id: string, props: DatabaseProps);
    private _createRdsInstance;
    private _createRdsCluster;
    private _createServerlessCluster;
    private _createServerlessV2Cluster;
}
export interface ContainerServiceProps {
    /**
     * The environment variables to pass to the keycloak container
     */
    readonly env?: {
        [key: string]: string;
    };
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
}
export declare class ContainerService extends Construct {
    readonly service: ecs.FargateService;
    readonly applicationLoadBalancer: elbv2.ApplicationLoadBalancer;
    readonly keycloakUserSecret: secretsmanager.ISecret;
    constructor(scope: Construct, id: string, props: ContainerServiceProps);
    private getImageUriFromMap;
    private getKeyCloakDockerImageUri;
}
