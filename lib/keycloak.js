"use strict";
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContainerService = exports.Database = exports.KeyCloak = exports.KeycloakVersion = void 0;
const JSII_RTTI_SYMBOL_1 = Symbol.for("jsii.rtti");
const cdk = require("aws-cdk-lib");
const aws_cdk_lib_1 = require("aws-cdk-lib");
const constructs_1 = require("constructs");
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
class KeycloakVersion {
    /**
     *
     * @param version cluster version number
     */
    constructor(version) {
        this.version = version;
    }
    /**
     * Custom cluster version
     * @param version custom version number
     */
    static of(version) { return new KeycloakVersion(version); }
}
exports.KeycloakVersion = KeycloakVersion;
_a = JSII_RTTI_SYMBOL_1;
KeycloakVersion[_a] = { fqn: "cdk-keycloak.KeycloakVersion", version: "0.0.0" };
/**
 * Keycloak version 12.0.4
 */
KeycloakVersion.V12_0_4 = KeycloakVersion.of('12.0.4');
/**
 * Keycloak version 15.0.0
 */
KeycloakVersion.V15_0_0 = KeycloakVersion.of('15.0.0');
/**
 * Keycloak version 15.0.1
 */
KeycloakVersion.V15_0_1 = KeycloakVersion.of('15.0.1');
/**
 * Keycloak version 15.0.2
 */
KeycloakVersion.V15_0_2 = KeycloakVersion.of('15.0.2');
/**
 * Keycloak version 16.1.1
 */
KeycloakVersion.V16_1_1 = KeycloakVersion.of('16.1.1');
/**
 * Keycloak version 17.0.1
 */
KeycloakVersion.V17_0_1 = KeycloakVersion.of('17.0.1');
/**
 * Keycloak version 18.0.2
 */
KeycloakVersion.V18_0_3 = KeycloakVersion.of('18.0.2');
/**
 * Keycloak version 19.0.3
 */
KeycloakVersion.V19_0_3 = KeycloakVersion.of('19.0.3');
/**
 * Keycloak version 20.0.5
 */
KeycloakVersion.V20_0_3 = KeycloakVersion.of('20.0.5');
/**
 * Keycloak version 21.0.0
 */
KeycloakVersion.V21_0_0 = KeycloakVersion.of('21.0.0');
/**
 * Keycloak version 21.0.1
 */
KeycloakVersion.V21_0_1 = KeycloakVersion.of('21.0.1');
const KEYCLOAK_DOCKER_IMAGE_URI_MAP = {
    'aws': 'quay.io/keycloak/keycloak:',
    'aws-cn': '048912060910.dkr.ecr.cn-northwest-1.amazonaws.com.cn/dockerhub/jboss/keycloak:',
};
class KeyCloak extends constructs_1.Construct {
    constructor(scope, id, props) {
        super(scope, id);
        const region = cdk.Stack.of(this).region;
        const regionIsResolved = !cdk.Token.isUnresolved(region);
        const { cpu = 2048, memoryLimitMiB = 4096, dbClusterInstances = 2 } = props;
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
            certificate: aws_cdk_lib_1.aws_certificatemanager.Certificate.fromCertificateArn(this, 'ACMCert', props.certificateArn),
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
        });
        this.applicationLoadBalancer = keycloakContainerService.applicationLoadBalancer;
        // this.networkLoadBalancer = keycloakContainerService.networkLoadBalancer;
        if (!cdk.Stack.of(this).templateOptions.description) {
            cdk.Stack.of(this).templateOptions.description = '(SO8021) - Deploy keycloak on AWS with cdk-keycloak construct library';
        }
    }
    addDatabase(props) {
        return new Database(this, 'Database', props);
    }
    addKeyCloakContainerService(props) {
        return new ContainerService(this, 'KeyCloakContainerSerivce', props);
    }
    _generateKeycloakSecret() {
        return new aws_cdk_lib_1.aws_secretsmanager.Secret(this, 'KCSecret', {
            generateSecretString: {
                generateStringKey: 'password',
                excludePunctuation: true,
                passwordLength: 12,
                secretStringTemplate: JSON.stringify({ username: 'keycloak' }),
            },
        });
    }
}
exports.KeyCloak = KeyCloak;
_b = JSII_RTTI_SYMBOL_1;
KeyCloak[_b] = { fqn: "cdk-keycloak.KeyCloak", version: "0.0.0" };
/**
 * Represents the database instance or database cluster
 */
class Database extends constructs_1.Construct {
    constructor(scope, id, props) {
        super(scope, id);
        this._mysqlListenerPort = 3306;
        this.vpc = props.vpc;
        let config;
        if (props.auroraServerless) {
            config = this._createServerlessCluster(props);
        }
        else if (props.auroraServerlessV2) {
            config = this._createServerlessV2Cluster(props);
        }
        else if (props.singleDbInstance) {
            config = this._createRdsInstance(props);
        }
        else {
            config = this._createRdsCluster(props);
        }
        this.secret = config.secret;
        // allow internally from the same security group
        config.connections.allowInternally(aws_cdk_lib_1.aws_ec2.Port.tcp(this._mysqlListenerPort));
        // allow from the whole vpc cidr
        config.connections.allowFrom(aws_cdk_lib_1.aws_ec2.Peer.ipv4(props.vpc.vpcCidrBlock), aws_cdk_lib_1.aws_ec2.Port.tcp(this._mysqlListenerPort));
        this.clusterEndpointHostname = config.endpoint;
        this.clusterIdentifier = config.identifier;
        this.connections = config.connections;
        printOutput(this, 'DBSecretArn', config.secret.secretArn);
        printOutput(this, 'clusterEndpointHostname', this.clusterEndpointHostname);
        printOutput(this, 'clusterIdentifier', this.clusterIdentifier);
    }
    _createRdsInstance(props) {
        const dbInstance = new aws_cdk_lib_1.aws_rds.DatabaseInstance(this, 'DBInstance', {
            vpc: props.vpc,
            databaseName: 'keycloak',
            vpcSubnets: props.databaseSubnets,
            engine: props.instanceEngine ?? aws_cdk_lib_1.aws_rds.DatabaseInstanceEngine.mysql({
                version: aws_cdk_lib_1.aws_rds.MysqlEngineVersion.VER_8_0_21,
            }),
            storageEncrypted: true,
            backupRetention: props.backupRetention ?? cdk.Duration.days(7),
            credentials: aws_cdk_lib_1.aws_rds.Credentials.fromGeneratedSecret('admin'),
            instanceType: props.instanceType ?? new aws_cdk_lib_1.aws_ec2.InstanceType('r5.large'),
            parameterGroup: aws_cdk_lib_1.aws_rds.ParameterGroup.fromParameterGroupName(this, 'ParameterGroup', 'default.mysql8.0'),
            deletionProtection: false,
            removalPolicy: props.removalPolicy ?? cdk.RemovalPolicy.RETAIN,
        });
        return {
            connections: dbInstance.connections,
            endpoint: dbInstance.dbInstanceEndpointAddress,
            identifier: dbInstance.instanceIdentifier,
            secret: dbInstance.secret,
        };
    }
    // create a RDS for MySQL DB cluster
    _createRdsCluster(props) {
        const dbCluster = new aws_cdk_lib_1.aws_rds.DatabaseCluster(this, 'DBCluster', {
            engine: props.clusterEngine ?? aws_cdk_lib_1.aws_rds.DatabaseClusterEngine.auroraMysql({
                version: aws_cdk_lib_1.aws_rds.AuroraMysqlEngineVersion.VER_2_09_1,
            }),
            instances: props.dbClusterInstances ?? 2,
            defaultDatabaseName: 'keycloak',
            deletionProtection: false,
            credentials: aws_cdk_lib_1.aws_rds.Credentials.fromGeneratedSecret('admin'),
            instanceProps: {
                vpc: props.vpc,
                vpcSubnets: props.databaseSubnets,
                instanceType: props.instanceType ?? new aws_cdk_lib_1.aws_ec2.InstanceType('r5.large'),
            },
            parameterGroup: aws_cdk_lib_1.aws_rds.ParameterGroup.fromParameterGroupName(this, 'ParameterGroup', 'default.aurora-mysql8.0'),
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
            secret: dbCluster.secret,
        };
    }
    _createServerlessCluster(props) {
        const dbCluster = new aws_cdk_lib_1.aws_rds.ServerlessCluster(this, 'AuroraServerlessCluster', {
            engine: aws_cdk_lib_1.aws_rds.DatabaseClusterEngine.AURORA_MYSQL,
            vpc: props.vpc,
            defaultDatabaseName: 'keycloak',
            vpcSubnets: props.databaseSubnets,
            credentials: aws_cdk_lib_1.aws_rds.Credentials.fromGeneratedSecret('admin'),
            backupRetention: props.backupRetention ?? cdk.Duration.days(7),
            deletionProtection: false,
            removalPolicy: props.removalPolicy ?? cdk.RemovalPolicy.RETAIN,
            parameterGroup: aws_cdk_lib_1.aws_rds.ParameterGroup.fromParameterGroupName(this, 'ParameterGroup', 'default.aurora-mysql8.0'),
        });
        return {
            connections: dbCluster.connections,
            endpoint: dbCluster.clusterEndpoint.hostname,
            identifier: dbCluster.clusterIdentifier,
            secret: dbCluster.secret,
        };
    }
    // create a RDS for MySQL DB cluster with Aurora Serverless v2
    _createServerlessV2Cluster(props) {
        const dbCluster = new aws_cdk_lib_1.aws_rds.DatabaseCluster(this, 'DBCluster', {
            engine: props.clusterEngine ?? aws_cdk_lib_1.aws_rds.DatabaseClusterEngine.auroraMysql({
                version: aws_cdk_lib_1.aws_rds.AuroraMysqlEngineVersion.VER_3_02_0,
            }),
            instances: props.dbClusterInstances ?? 2,
            defaultDatabaseName: 'keycloak',
            deletionProtection: false,
            credentials: aws_cdk_lib_1.aws_rds.Credentials.fromGeneratedSecret('admin'),
            instanceProps: {
                vpc: props.vpc,
                vpcSubnets: props.databaseSubnets,
                // Specify serverless Instance Type
                instanceType: new aws_cdk_lib_1.aws_ec2.InstanceType('serverless'),
            },
            // Set default parameter group for Aurora MySQL 8.0
            parameterGroup: aws_cdk_lib_1.aws_rds.ParameterGroup.fromParameterGroupName(this, 'ParameterGroup', 'default.aurora-mysql8.0'),
            backup: {
                retention: props.backupRetention ?? cdk.Duration.days(7),
            },
            storageEncrypted: true,
            removalPolicy: props.removalPolicy ?? cdk.RemovalPolicy.RETAIN,
        });
        // Set Serverless V2 Scaling Configuration
        // TODO: Use cleaner way to set scaling configuration.
        // https://github.com/aws/aws-cdk/issues/20197
        dbCluster.node.findChild('Resource').serverlessV2ScalingConfiguration = {
            minCapacity: props.minCapacity ?? 0.5,
            maxCapacity: props.maxCapacity ?? 10,
        };
        return {
            connections: dbCluster.connections,
            endpoint: dbCluster.clusterEndpoint.hostname,
            identifier: dbCluster.clusterIdentifier,
            secret: dbCluster.secret,
        };
    }
}
exports.Database = Database;
_c = JSII_RTTI_SYMBOL_1;
Database[_c] = { fqn: "cdk-keycloak.Database", version: "0.0.0" };
class ContainerService extends constructs_1.Construct {
    constructor(scope, id, props) {
        super(scope, id);
        const { cpu, memoryLimitMiB } = props;
        const region = cdk.Stack.of(this).region;
        const containerPort = 8080;
        const connectionString = `jdbc:mysql://${props.database.clusterEndpointHostname}:3306/keycloak`;
        // const protocol = elbv2.ApplicationProtocol.HTTP;
        const entryPoint = ['/opt/keycloak/bin/kc.sh', 'start', '--optimized'];
        const s3PingBucket = new aws_cdk_lib_1.aws_s3.Bucket(this, 'keycloak_s3_ping', { removalPolicy: aws_cdk_lib_1.RemovalPolicy.DESTROY });
        const image = props.containerImage ?? aws_cdk_lib_1.aws_ecs.ContainerImage.fromRegistry(this.getKeyCloakDockerImageUri(props.keycloakVersion.version));
        const secrets = {
            KC_DB_PASSWORD: aws_cdk_lib_1.aws_ecs.Secret.fromSecretsManager(props.database.secret, 'password'),
            KEYCLOAK_ADMIN: aws_cdk_lib_1.aws_ecs.Secret.fromSecretsManager(props.keycloakSecret, 'username'),
            KEYCLOAK_ADMIN_PASSWORD: aws_cdk_lib_1.aws_ecs.Secret.fromSecretsManager(props.keycloakSecret, 'password'),
        };
        const portMappings = [
            { containerPort: containerPort },
            { containerPort: 7800 },
            { containerPort: 57800 },
        ];
        const vpc = props.vpc;
        const cluster = new aws_cdk_lib_1.aws_ecs.Cluster(this, 'Cluster', { vpc, containerInsights: true });
        cluster.node.addDependency(props.database);
        const executionRole = new aws_cdk_lib_1.aws_iam.Role(this, 'TaskRole', {
            assumedBy: new aws_cdk_lib_1.aws_iam.CompositePrincipal(new aws_cdk_lib_1.aws_iam.ServicePrincipal('ecs.amazonaws.com'), new aws_cdk_lib_1.aws_iam.ServicePrincipal('ecs-tasks.amazonaws.com')),
        });
        const taskDefinition = new aws_cdk_lib_1.aws_ecs.FargateTaskDefinition(this, 'TaskDef', {
            cpu,
            memoryLimitMiB,
            executionRole,
        });
        const logGroup = new aws_cdk_lib_1.aws_logs.LogGroup(this, 'LogGroup', {
            retention: aws_cdk_lib_1.aws_logs.RetentionDays.ONE_MONTH,
            removalPolicy: cdk.RemovalPolicy.RETAIN,
        });
        const s3User = new aws_cdk_lib_1.aws_iam.User(this, 'S3KeycloakUser');
        const accessKey = new aws_cdk_lib_1.aws_iam.AccessKey(this, 'S3KeycloakUserAccessKey', { user: s3User });
        this.keycloakUserSecret = new aws_cdk_lib_1.aws_secretsmanager.Secret(this, 'S3KeycloakUserSecret', {
            secretStringValue: accessKey.secretAccessKey,
        });
        s3PingBucket.grantReadWrite(s3User);
        const environment = {
            JAVA_OPTS_APPEND: `
      -Djgroups.s3.region_name=${region}
      -Djgroups.s3.bucket_name=${s3PingBucket.bucketName}
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
            KC_HOSTNAME: props.hostname,
            KC_HOSTNAME_STRICT_BACKCHANNEL: 'true',
            KC_PROXY: 'edge',
            KC_HEALTH_ENABLED: 'true',
        };
        const kc = taskDefinition.addContainer('keycloak', {
            image,
            entryPoint,
            environment: Object.assign(environment, props.env),
            secrets,
            logging: aws_cdk_lib_1.aws_ecs.LogDrivers.awsLogs({
                streamPrefix: 'keycloak',
                logGroup,
            }),
        });
        kc.addPortMappings(...portMappings);
        // we need extra privileges to fetch keycloak docker images from China mirror site
        taskDefinition.executionRole?.addManagedPolicy(aws_cdk_lib_1.aws_iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEC2ContainerRegistryReadOnly'));
        this.service = new aws_cdk_lib_1.aws_ecs.FargateService(this, 'Service', {
            cluster,
            taskDefinition,
            circuitBreaker: props.circuitBreaker ? { rollback: true } : undefined,
            desiredCount: props.nodeCount ?? 2,
            healthCheckGracePeriod: cdk.Duration.seconds(120),
        });
        this.service.connections.allowFrom(this.service.connections, aws_cdk_lib_1.aws_ec2.Port.tcp(7800), 'kc jgroups-tcp');
        this.service.connections.allowFrom(this.service.connections, aws_cdk_lib_1.aws_ec2.Port.tcp(57800), 'kc jgroups-tcp-fd');
        s3PingBucket.grantReadWrite(taskDefinition.taskRole);
        if (props.autoScaleTask) {
            const minCapacity = props.autoScaleTask.min ?? props.nodeCount ?? 2;
            const scaling = this.service.autoScaleTaskCount({
                minCapacity,
                maxCapacity: props.autoScaleTask.max ?? minCapacity + 5,
            });
            scaling.scaleOnCpuUtilization('CpuScaling', {
                targetUtilizationPercent: props.autoScaleTask.targetCpuUtilization ?? 75,
            });
        }
        ;
        // listener protocol 'TLS' is not supported with a target group with the target-type 'ALB'
        this.applicationLoadBalancer = new aws_cdk_lib_1.aws_elasticloadbalancingv2.ApplicationLoadBalancer(this, 'ALB', {
            vpc,
            vpcSubnets: props.publicSubnets,
            internetFacing: true,
        });
        printOutput(this, 'EndpointURL', `https://${this.applicationLoadBalancer.loadBalancerDnsName}`);
        const listener = this.applicationLoadBalancer.addListener('ALB_HttpsListener', {
            protocol: aws_cdk_lib_1.aws_elasticloadbalancingv2.ApplicationProtocol.HTTPS,
            certificates: [{ certificateArn: props.certificate.certificateArn }],
        });
        // "If the target type is ALB, the target must have at least one listener that matches the target group port or any specified port overrides
        listener.addTargets('ECSTarget', {
            protocol: aws_cdk_lib_1.aws_elasticloadbalancingv2.ApplicationProtocol.HTTP,
            slowStart: cdk.Duration.seconds(60),
            stickinessCookieDuration: props.stickinessCookieDuration ?? cdk.Duration.days(1),
            targets: [this.service],
            healthCheck: {
                healthyThresholdCount: 3,
            },
        });
        // allow task execution role to read the secrets
        props.database.secret.grantRead(taskDefinition.executionRole);
        props.keycloakSecret.grantRead(taskDefinition.executionRole);
        // allow ecs task connect to database
        props.database.connections.allowDefaultPortFrom(this.service);
        // create a bastion host
        if (props.bastion === true) {
            const bast = new aws_cdk_lib_1.aws_ec2.BastionHostLinux(this, 'Bast', {
                vpc,
                instanceType: new aws_cdk_lib_1.aws_ec2.InstanceType('t3.small'),
            });
            props.database.connections.allowDefaultPortFrom(bast);
        }
    }
    getImageUriFromMap(map, version, id) {
        const stack = cdk.Stack.of(this);
        if (cdk.Token.isUnresolved(stack.region)) {
            const mapping = {};
            for (let [partition, uri] of Object.entries(map)) {
                uri += version;
                mapping[partition] = { uri };
            }
            const imageMap = new cdk.CfnMapping(this, id, { mapping });
            return imageMap.findInMap(cdk.Aws.PARTITION, 'uri');
        }
        else {
            if (stack.region.startsWith('cn-')) {
                return map['aws-cn'] += version;
            }
            else {
                return map.aws += version;
            }
        }
    }
    getKeyCloakDockerImageUri(version) {
        return this.getImageUriFromMap(KEYCLOAK_DOCKER_IMAGE_URI_MAP, version, 'KeycloakImageMap');
    }
}
exports.ContainerService = ContainerService;
_d = JSII_RTTI_SYMBOL_1;
ContainerService[_d] = { fqn: "cdk-keycloak.ContainerService", version: "0.0.0" };
/**
 * Create or import VPC
 * @param scope the cdk scope
 */
function getOrCreateVpc(scope) {
    // use an existing vpc or create a new one
    return scope.node.tryGetContext('use_default_vpc') === '1' ?
        aws_cdk_lib_1.aws_ec2.Vpc.fromLookup(scope, 'Vpc', { isDefault: true }) :
        scope.node.tryGetContext('use_vpc_id') ?
            aws_cdk_lib_1.aws_ec2.Vpc.fromLookup(scope, 'Vpc', { vpcId: scope.node.tryGetContext('use_vpc_id') }) :
            new aws_cdk_lib_1.aws_ec2.Vpc(scope, 'Vpc', { maxAzs: 3, natGateways: 1 });
}
function printOutput(scope, id, key) {
    new cdk.CfnOutput(scope, id, { value: String(key) });
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoia2V5Y2xvYWsuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMva2V5Y2xvYWsudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSxtQ0FBbUM7QUFDbkMsNkNBV3FCO0FBQ3JCLDJDQUF1QztBQUV2Qyw4Q0FBOEM7QUFDOUMsc0hBQXNIO0FBQ3RILE1BQU0sbUNBQW1DLEdBQUc7SUFDMUMsV0FBVztJQUNYLFdBQVc7SUFDWCxXQUFXO0lBQ1gsV0FBVztJQUNYLFlBQVk7SUFDWixnQkFBZ0I7SUFDaEIsZ0JBQWdCO0lBQ2hCLGdCQUFnQjtJQUNoQixnQkFBZ0I7SUFDaEIsY0FBYztJQUNkLGNBQWM7SUFDZCxXQUFXO0lBQ1gsV0FBVztJQUNYLFdBQVc7SUFDWCxnQkFBZ0I7Q0FDakIsQ0FBQztBQUVGOztHQUVHO0FBQ0gsTUFBYSxlQUFlO0lBNkQxQjs7O09BR0c7SUFDSCxZQUFvQyxPQUFlO1FBQWYsWUFBTyxHQUFQLE9BQU8sQ0FBUTtJQUFJLENBQUM7SUFUeEQ7OztPQUdHO0lBQ0ksTUFBTSxDQUFDLEVBQUUsQ0FBQyxPQUFlLElBQUksT0FBTyxJQUFJLGVBQWUsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUM7O0FBNUQ1RSwwQ0FrRUM7OztBQWpFQzs7R0FFRztBQUNvQix1QkFBTyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUM7QUFFOUQ7O0dBRUc7QUFDb0IsdUJBQU8sR0FBRyxlQUFlLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBRTlEOztHQUVHO0FBQ29CLHVCQUFPLEdBQUcsZUFBZSxDQUFDLEVBQUUsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUU5RDs7R0FFRztBQUNvQix1QkFBTyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUM7QUFFOUQ7O0dBRUc7QUFDb0IsdUJBQU8sR0FBRyxlQUFlLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBRTlE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QyxDQUFDLENBQUM7WUFDckYsSUFBSSxxQkFBRyxDQUFDLEdBQUcsQ0FBQyxLQUFLLEVBQUUsS0FBSyxFQUFFLEVBQUUsTUFBTSxFQUFFLENBQUMsRUFBRSxXQUFXLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUMvRCxDQUFDO0FBRUQsU0FBUyxXQUFXLENBQUMsS0FBZ0IsRUFBRSxFQUFVLEVBQUUsR0FBb0I7SUFDckUsSUFBSSxHQUFHLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxFQUFFLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUN2RCxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgY2RrIGZyb20gJ2F3cy1jZGstbGliJztcbmltcG9ydCB7XG4gIGF3c19jZXJ0aWZpY2F0ZW1hbmFnZXIgYXMgY2VydG1ncixcbiAgYXdzX2VjMiBhcyBlYzIsXG4gIGF3c19lY3MgYXMgZWNzLFxuICBhd3NfZWxhc3RpY2xvYWRiYWxhbmNpbmd2MiBhcyBlbGJ2MixcbiAgYXdzX2lhbSBhcyBpYW0sXG4gIGF3c19sb2dzIGFzIGxvZ3MsXG4gIGF3c19yZHMgYXMgcmRzLFxuICBhd3NfczMgYXMgczMsXG4gIGF3c19zZWNyZXRzbWFuYWdlciBhcyBzZWNyZXRzbWFuYWdlcixcbiAgUmVtb3ZhbFBvbGljeSxcbn0gZnJvbSAnYXdzLWNkay1saWInO1xuaW1wb3J0IHsgQ29uc3RydWN0IH0gZnJvbSAnY29uc3RydWN0cyc7XG5cbi8vIHJlZ2lvbmFsIGF2YWlsaWJpbGl0eSBmb3IgYXVyb3JhIHNlcnZlcmxlc3Ncbi8vIHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUkRTL2xhdGVzdC9BdXJvcmFVc2VyR3VpZGUvQ29uY2VwdHMuQXVyb3JhRmVhdHVyZXNSZWdpb25zREJFbmdpbmVzLmdyaWRzLmh0bWxcbmNvbnN0IEFVUk9SQV9TRVJWRVJMRVNTX1NVUFBPUlRFRF9SRUdJT05TID0gW1xuICAndXMtZWFzdC0xJyxcbiAgJ3VzLWVhc3QtMicsXG4gICd1cy13ZXN0LTEnLFxuICAndXMtd2VzdC0yJyxcbiAgJ2FwLXNvdXRoLTEnLFxuICAnYXAtbm9ydGhlYXN0LTEnLFxuICAnYXAtbm9ydGhlYXN0LTInLFxuICAnYXAtc291dGhlYXN0LTEnLFxuICAnYXAtc291dGhlYXN0LTInLFxuICAnY2EtY2VudHJhbC0xJyxcbiAgJ2V1LWNlbnRyYWwtMScsXG4gICdldS13ZXN0LTEnLFxuICAnZXUtd2VzdC0yJyxcbiAgJ2V1LXdlc3QtMycsXG4gICdjbi1ub3J0aHdlc3QtMScsXG5dO1xuXG4vKipcbiAqIEtleWNsb2FrICB2ZXJzaW9uXG4gKi9cbmV4cG9ydCBjbGFzcyBLZXljbG9ha1ZlcnNpb24ge1xuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxMi4wLjRcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjEyXzBfNCA9IEtleWNsb2FrVmVyc2lvbi5vZignMTIuMC40Jyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTUuMC4wXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxNV8wXzAgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE1LjAuMCcpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE1LjAuMVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTVfMF8xID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxNS4wLjEnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxNS4wLjJcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE1XzBfMiA9IEtleWNsb2FrVmVyc2lvbi5vZignMTUuMC4yJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTYuMS4xXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxNl8xXzEgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE2LjEuMScpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE3LjAuMVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTdfMF8xID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxNy4wLjEnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxOC4wLjJcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE4XzBfMyA9IEtleWNsb2FrVmVyc2lvbi5vZignMTguMC4yJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTkuMC4zXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxOV8wXzMgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE5LjAuMycpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDIwLjAuNVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMjBfMF8zID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcyMC4wLjUnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAyMS4wLjBcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjIxXzBfMCA9IEtleWNsb2FrVmVyc2lvbi5vZignMjEuMC4wJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMjEuMC4xXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYyMV8wXzEgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzIxLjAuMScpO1xuXG4gIC8qKlxuICAgKiBDdXN0b20gY2x1c3RlciB2ZXJzaW9uXG4gICAqIEBwYXJhbSB2ZXJzaW9uIGN1c3RvbSB2ZXJzaW9uIG51bWJlclxuICAgKi9cbiAgcHVibGljIHN0YXRpYyBvZih2ZXJzaW9uOiBzdHJpbmcpIHsgcmV0dXJuIG5ldyBLZXljbG9ha1ZlcnNpb24odmVyc2lvbik7IH1cbiAgLyoqXG4gICAqXG4gICAqIEBwYXJhbSB2ZXJzaW9uIGNsdXN0ZXIgdmVyc2lvbiBudW1iZXJcbiAgICovXG4gIHByaXZhdGUgY29uc3RydWN0b3IocHVibGljIHJlYWRvbmx5IHZlcnNpb246IHN0cmluZykgeyB9XG59XG5cbmludGVyZmFjZSBkb2NrZXJJbWFnZU1hcCB7XG4gICdhd3MnOiBzdHJpbmc7XG4gICdhd3MtY24nOiBzdHJpbmc7XG59XG5cbmNvbnN0IEtFWUNMT0FLX0RPQ0tFUl9JTUFHRV9VUklfTUFQOiBkb2NrZXJJbWFnZU1hcCA9IHtcbiAgJ2F3cyc6ICdxdWF5LmlvL2tleWNsb2FrL2tleWNsb2FrOicsXG4gICdhd3MtY24nOiAnMDQ4OTEyMDYwOTEwLmRrci5lY3IuY24tbm9ydGh3ZXN0LTEuYW1hem9uYXdzLmNvbS5jbi9kb2NrZXJodWIvamJvc3Mva2V5Y2xvYWs6Jyxcbn07XG5cbi8qKlxuICogVGhlIEVDUyB0YXNrIGF1dG9zY2FsaW5nIGRlZmluaXRpb25cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBBdXRvU2NhbGVUYXNrIHtcbiAgLyoqXG4gICAqIFRoZSBtaW5pbWFsIGNvdW50IG9mIHRoZSB0YXNrIG51bWJlclxuICAgKlxuICAgKiBAZGVmYXVsdCAtIG5vZGVDb3VudFxuICAgKi9cbiAgcmVhZG9ubHkgbWluPzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIG1heGltYWwgY291bnQgb2YgdGhlIHRhc2sgbnVtYmVyXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gbWluICsgNVxuICAgKi9cbiAgcmVhZG9ubHkgbWF4PzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIHRhcmdldCBjcHUgdXRpbGl6YXRpb24gZm9yIHRoZSBzZXJ2aWNlIGF1dG9zY2FsaW5nXG4gICAqXG4gICAqIEBkZWZhdWx0IDc1XG4gICAqL1xuICByZWFkb25seSB0YXJnZXRDcHVVdGlsaXphdGlvbj86IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBLZXlDbG9ha1Byb3BzIHtcbiAgLyoqXG4gICAqIFRoZSBLZXljbG9hayB2ZXJzaW9uIGZvciB0aGUgY2x1c3Rlci5cbiAgICovXG4gIHJlYWRvbmx5IGtleWNsb2FrVmVyc2lvbjogS2V5Y2xvYWtWZXJzaW9uO1xuICAvKipcbiAgICogVGhlIGVudmlyb25tZW50IHZhcmlhYmxlcyB0byBwYXNzIHRvIHRoZSBrZXljbG9hayBjb250YWluZXJcbiAgICovXG4gIHJlYWRvbmx5IGVudj86IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIH07XG4gIC8qKlxuICAgKiBWUEMgZm9yIHRoZSB3b3JrbG9hZFxuICAgKi9cbiAgcmVhZG9ubHkgdnBjPzogZWMyLklWcGM7XG4gIC8qKlxuICAgKiBBQ00gY2VydGlmaWNhdGUgQVJOIHRvIGltcG9ydFxuICAgKi9cbiAgcmVhZG9ubHkgY2VydGlmaWNhdGVBcm46IHN0cmluZztcbiAgLyoqXG4gICAqIENyZWF0ZSBhIGJhc3Rpb24gaG9zdCBmb3IgZGVidWdnaW5nIG9yIHRyb3VibGUtc2hvb3RpbmdcbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGJhc3Rpb24/OiBib29sZWFuO1xuICAvKipcbiAgICogTnVtYmVyIG9mIGtleWNsb2FrIG5vZGUgaW4gdGhlIGNsdXN0ZXJcbiAgICpcbiAgICogQGRlZmF1bHQgMlxuICAgKi9cbiAgcmVhZG9ubHkgbm9kZUNvdW50PzogbnVtYmVyO1xuICAvKipcbiAgICogVlBDIHB1YmxpYyBzdWJuZXRzIGZvciBBTEJcbiAgICpcbiAgICogQGRlZmF1bHQgLSBWUEMgcHVibGljIHN1Ym5ldHNcbiAgICovXG4gIHJlYWRvbmx5IHB1YmxpY1N1Ym5ldHM/OiBlYzIuU3VibmV0U2VsZWN0aW9uO1xuICAvKipcbiAgICogVlBDIHByaXZhdGUgc3VibmV0cyBmb3Iga2V5Y2xvYWsgc2VydmljZVxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFZQQyBwcml2YXRlIHN1Ym5ldHNcbiAgICovXG4gIHJlYWRvbmx5IHByaXZhdGVTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFZQQyBzdWJuZXRzIGZvciBkYXRhYmFzZVxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFZQQyBpc29sYXRlZCBzdWJuZXRzXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZVN1Ym5ldHM/OiBlYzIuU3VibmV0U2VsZWN0aW9uO1xuICAvKipcbiAgICogRGF0YWJhc2UgaW5zdGFuY2UgdHlwZVxuICAgKlxuICAgKiBAZGVmYXVsdCByNS5sYXJnZVxuICAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2VJbnN0YW5jZVR5cGU/OiBlYzIuSW5zdGFuY2VUeXBlO1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGluc3RhbmNlIGVuZ2luZVxuICAgKlxuICAgKiBAZGVmYXVsdCAtIE15U1FMIDguMC4yMVxuICAgKi9cbiAgcmVhZG9ubHkgaW5zdGFuY2VFbmdpbmU/OiByZHMuSUluc3RhbmNlRW5naW5lO1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGNsdXN0ZXIgZW5naW5lXG4gICAqXG4gICAqIEBkZWZhdWx0IHJkcy5BdXJvcmFNeXNxbEVuZ2luZVZlcnNpb24uVkVSXzJfMDlfMVxuICAgKi9cbiAgcmVhZG9ubHkgY2x1c3RlckVuZ2luZT86IHJkcy5JQ2x1c3RlckVuZ2luZTtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gdXNlIGF1cm9yYSBzZXJ2ZXJsZXNzLiBXaGVuIGVuYWJsZWQsIHRoZSBgZGF0YWJhc2VJbnN0YW5jZVR5cGVgIGFuZFxuICAgKiBgZW5naW5lYCB3aWxsIGJlIGlnbm9yZWQuIFRoZSBgcmRzLkRhdGFiYXNlQ2x1c3RlckVuZ2luZS5BVVJPUkFfTVlTUUxgIHdpbGwgYmUgdXNlZCBhc1xuICAgKiB0aGUgZGVmYXVsdCBjbHVzdGVyIGVuZ2luZSBpbnN0ZWFkLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYXVyb3JhU2VydmVybGVzcz86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHVzZSBhdXJvcmEgc2VydmVybGVzcyB2Mi4gV2hlbiBlbmFibGVkLCB0aGUgYGRhdGFiYXNlSW5zdGFuY2VUeXBlYCB3aWxsIGJlIGlnbm9yZWQuXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBhdXJvcmFTZXJ2ZXJsZXNzVjI/OiBib29sZWFuO1xuICAvKipcbiAgICogV2hldGhlciB0byB1c2Ugc2luZ2xlIFJEUyBpbnN0YW5jZSByYXRoZXIgdGhhbiBSRFMgY2x1c3Rlci4gTm90IHJlY29tbWVuZGVkIGZvciBwcm9kdWN0aW9uLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgc2luZ2xlRGJJbnN0YW5jZT86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBkYXRhYmFzZSBiYWNrdXAgcmV0ZW5zaW9uXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gNyBkYXlzXG4gICAqL1xuICByZWFkb25seSBiYWNrdXBSZXRlbnRpb24/OiBjZGsuRHVyYXRpb247XG4gIC8qKlxuICAgKiBUaGUgc3RpY2t5IHNlc3Npb24gZHVyYXRpb24gZm9yIHRoZSBrZXljbG9hayB3b3JrbG9hZCB3aXRoIEFMQi5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBvbmUgZGF5XG4gICAqL1xuICByZWFkb25seSBzdGlja2luZXNzQ29va2llRHVyYXRpb24/OiBjZGsuRHVyYXRpb247XG4gIC8qKlxuICAgKiBBdXRvc2NhbGluZyBmb3IgdGhlIEVDUyBTZXJ2aWNlXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gbm8gZWNzIHNlcnZpY2UgYXV0b3NjYWxpbmdcbiAgICovXG4gIHJlYWRvbmx5IGF1dG9TY2FsZVRhc2s/OiBBdXRvU2NhbGVUYXNrO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHB1dCB0aGUgbG9hZCBiYWxhbmNlciBpbiB0aGUgcHVibGljIG9yIHByaXZhdGUgc3VibmV0c1xuICAgKlxuICAgKiBAZGVmYXVsdCB0cnVlXG4gICAqL1xuICByZWFkb25seSBpbnRlcm5ldEZhY2luZz86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSBob3N0bmFtZSB0byB1c2UgZm9yIHRoZSBrZXljbG9hayBzZXJ2ZXJcbiAgICovXG4gIHJlYWRvbmx5IGhvc3RuYW1lPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgbWluaW11bSBudW1iZXIgb2YgQXVyb3JhIFNlcnZlcmxlc3MgVjIgY2FwYWNpdHkgdW5pdHMuXG4gICAqXG4gICAqIEBkZWZhdWx0IDAuNVxuICAqL1xuICByZWFkb25seSBkYXRhYmFzZU1pbkNhcGFjaXR5PzogbnVtYmVyO1xuXG4gIC8qKlxuICAqIFRoZSBtYXhpbXVtIG51bWJlciBvZiBBdXJvcmEgU2VydmVybGVzcyBWMiBjYXBhY2l0eSB1bml0cy5cbiAgKlxuICAgKiBAZGVmYXVsdCAxMFxuICAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2VNYXhDYXBhY2l0eT86IG51bWJlcjtcblxuICAvKipcbiAgICogQ29udHJvbHMgd2hhdCBoYXBwZW5zIHRvIHRoZSBkYXRhYmFzZSBpZiBpdCBzdG9wcyBiZWluZyBtYW5hZ2VkIGJ5IENsb3VkRm9ybWF0aW9uXG4gICAqXG4gICAqIEBkZWZhdWx0IFJlbW92YWxQb2xpY3kuUkVUQUlOXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZVJlbW92YWxQb2xpY3k/OiBjZGsuUmVtb3ZhbFBvbGljeTtcblxuXG4gIC8qKlxuICAgKiBPdmVycmlkZXMgdGhlIGRlZmF1bHQgaW1hZ2VcbiAgICpcbiAgICogQGRlZmF1bHQgcXVheS5pby9rZXljbG9hay9rZXljbG9hazoke0tFWUNMT0FLX1ZFUlNJT059XG4gICAqL1xuICByZWFkb25seSBjb250YWluZXJJbWFnZT86IGVjcy5Db250YWluZXJJbWFnZTtcblxuICAvKipcbiAgICogVGhlIG51bWJlciBvZiBjcHUgdW5pdHMgdXNlZCBieSB0aGUgS2V5Y2xvYWsgdGFzay5cbiAgICogWW91IG11c3QgdXNlIG9uZSBvZiB0aGUgZm9sbG93aW5nIHZhbHVlcywgd2hpY2ggZGV0ZXJtaW5lcyB5b3VyIHJhbmdlIG9mIHZhbGlkIHZhbHVlcyBmb3IgdGhlIG1lbW9yeSBwYXJhbWV0ZXI6XG4gICAqIDI1NiAoLjI1IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IDUxMiAoMC41IEdCKSwgMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpXG4gICAqIDUxMiAoLjUgdkNQVSkgLSBBdmFpbGFibGUgbWVtb3J5IHZhbHVlczogMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpLCAzMDcyICgzIEdCKSwgNDA5NiAoNCBHQilcbiAgICogMTAyNCAoMSB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpLCA1MTIwICg1IEdCKSwgNjE0NCAoNiBHQiksIDcxNjggKDcgR0IpLCA4MTkyICg4IEdCKVxuICAgKiAyMDQ4ICgyIHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gNDA5NiAoNCBHQikgYW5kIDE2Mzg0ICgxNiBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKVxuICAgKiA0MDk2ICg0IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gODE5MiAoOCBHQikgYW5kIDMwNzIwICgzMCBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKVxuICAgKiA4MTkyICg4IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gMTYzODQgKDE2IEdCKSBhbmQgNjE0NDAgKDYwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDQwOTYgKDQgR0IpXG4gICAqIDE2Mzg0ICgxNiB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiBCZXR3ZWVuIDMyNzY4ICgzMiBHQikgYW5kIDEyMjg4MCAoMTIwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDgxOTIgKDggR0IpXG4gICAqXG4gICAqIEBkZWZhdWx0IDIwNDhcbiAgICovXG4gIHJlYWRvbmx5IGNwdT86IG51bWJlcjtcblxuICAvKipcbiAgICogVGhlIGFtb3VudCAoaW4gTWlCKSBvZiBtZW1vcnkgdXNlZCBieSB0aGUgdGFzay5cbiAgICogWW91IG11c3QgdXNlIG9uZSBvZiB0aGUgZm9sbG93aW5nIHZhbHVlcywgd2hpY2ggZGV0ZXJtaW5lcyB5b3VyIHJhbmdlIG9mIHZhbGlkIHZhbHVlcyBmb3IgdGhlIGNwdSBwYXJhbWV0ZXI6XG4gICAqIDUxMiAoMC41IEdCKSwgMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDI1NiAoLjI1IHZDUFUpXG4gICAqIDEwMjQgKDEgR0IpLCAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDUxMiAoLjUgdkNQVSlcbiAgICogMjA0OCAoMiBHQiksIDMwNzIgKDMgR0IpLCA0MDk2ICg0IEdCKSwgNTEyMCAoNSBHQiksIDYxNDQgKDYgR0IpLCA3MTY4ICg3IEdCKSwgODE5MiAoOCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMTAyNCAoMSB2Q1BVKVxuICAgKiBCZXR3ZWVuIDQwOTYgKDQgR0IpIGFuZCAxNjM4NCAoMTYgR0IpIGluIGluY3JlbWVudHMgb2YgMTAyNCAoMSBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMjA0OCAoMiB2Q1BVKVxuICAgKiBCZXR3ZWVuIDgxOTIgKDggR0IpIGFuZCAzMDcyMCAoMzAgR0IpIGluIGluY3JlbWVudHMgb2YgMTAyNCAoMSBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogNDA5NiAoNCB2Q1BVKVxuICAgKiBCZXR3ZWVuIDE2Mzg0ICgxNiBHQikgYW5kIDYxNDQwICg2MCBHQikgaW4gaW5jcmVtZW50cyBvZiA0MDk2ICg0IEdCKSAtIEF2YWlsYWJsZSBjcHUgdmFsdWVzOiA4MTkyICg4IHZDUFUpXG4gICAqIEJldHdlZW4gMzI3NjggKDMyIEdCKSBhbmQgMTIyODgwICgxMjAgR0IpIGluIGluY3JlbWVudHMgb2YgODE5MiAoOCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMTYzODQgKDE2IHZDUFUpXG4gICAqXG4gICAqIEBkZWZhdWx0IDQwOTZcbiAgICovXG4gIHJlYWRvbmx5IG1lbW9yeUxpbWl0TWlCPzogbnVtYmVyO1xuXG5cbiAgLyoqXG4gICAqIE51bWJlciBvZiBpbnN0YW5jZXMgdG8gc3Bhd24gaW4gdGhlIGRhdGFiYXNlIGNsdXN0ZXIgKGZvciBjbHVzdGVyIGRhdGFiYXNlIG9wdGlvbnMgb25seSkuXG4gICAqIEhhcyB0byBiZSBhdCBsZWFzdCAxLlxuICAgKlxuICAgKiBAZGVmYXVsdCAyXG4gICAqL1xuICByZWFkb25seSBkYkNsdXN0ZXJJbnN0YW5jZXM/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBjbGFzcyBLZXlDbG9hayBleHRlbmRzIENvbnN0cnVjdCB7XG4gIHJlYWRvbmx5IHZwYzogZWMyLklWcGM7XG4gIHJlYWRvbmx5IGRiPzogRGF0YWJhc2U7XG4gIHJlYWRvbmx5IGFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyOiBlbGJ2Mi5BcHBsaWNhdGlvbkxvYWRCYWxhbmNlcjtcbiAgLy8gcmVhZG9ubHkgbmV0d29ya0xvYWRCYWxhbmNlcjogZWxidjIuTmV0d29ya0xvYWRCYWxhbmNlcjtcbiAgcmVhZG9ubHkga2V5Y2xvYWtTZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBLZXlDbG9ha1Byb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkKTtcblxuICAgIGNvbnN0IHJlZ2lvbiA9IGNkay5TdGFjay5vZih0aGlzKS5yZWdpb247XG4gICAgY29uc3QgcmVnaW9uSXNSZXNvbHZlZCA9ICFjZGsuVG9rZW4uaXNVbnJlc29sdmVkKHJlZ2lvbik7XG4gICAgY29uc3QgeyBjcHUgPSAyMDQ4LCBtZW1vcnlMaW1pdE1pQiA9NDA5NiwgZGJDbHVzdGVySW5zdGFuY2VzID0gMiB9ID0gcHJvcHM7XG5cbiAgICBpZiAocHJvcHMuYXVyb3JhU2VydmVybGVzcyAmJiByZWdpb25Jc1Jlc29sdmVkICYmICFBVVJPUkFfU0VSVkVSTEVTU19TVVBQT1JURURfUkVHSU9OUy5pbmNsdWRlcyhyZWdpb24pKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYEF1cm9yYSBzZXJ2ZXJsZXNzIGlzIG5vdCBzdXBwb3J0ZWQgaW4gJHtyZWdpb259YCk7XG4gICAgfVxuXG4gICAgdGhpcy5rZXljbG9ha1NlY3JldCA9IHRoaXMuX2dlbmVyYXRlS2V5Y2xvYWtTZWNyZXQoKTtcbiAgICB0aGlzLnZwYyA9IHByb3BzLnZwYyA/PyBnZXRPckNyZWF0ZVZwYyh0aGlzKTtcblxuICAgIHRoaXMuZGIgPSB0aGlzLmFkZERhdGFiYXNlKHtcbiAgICAgIHZwYzogdGhpcy52cGMsXG4gICAgICBkYXRhYmFzZVN1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgIGluc3RhbmNlVHlwZTogcHJvcHMuZGF0YWJhc2VJbnN0YW5jZVR5cGUsXG4gICAgICBpbnN0YW5jZUVuZ2luZTogcHJvcHMuaW5zdGFuY2VFbmdpbmUsXG4gICAgICBjbHVzdGVyRW5naW5lOiBwcm9wcy5jbHVzdGVyRW5naW5lLFxuICAgICAgYXVyb3JhU2VydmVybGVzczogZmFsc2UsXG4gICAgICBhdXJvcmFTZXJ2ZXJsZXNzVjI6IGZhbHNlLFxuICAgICAgc2luZ2xlRGJJbnN0YW5jZTogcHJvcHMuc2luZ2xlRGJJbnN0YW5jZSxcbiAgICAgIGJhY2t1cFJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uLFxuICAgICAgbWF4Q2FwYWNpdHk6IHByb3BzLmRhdGFiYXNlTWF4Q2FwYWNpdHksXG4gICAgICBtaW5DYXBhY2l0eTogcHJvcHMuZGF0YWJhc2VNaW5DYXBhY2l0eSxcbiAgICAgIHJlbW92YWxQb2xpY3k6IHByb3BzLmRhdGFiYXNlUmVtb3ZhbFBvbGljeSxcbiAgICAgIGRiQ2x1c3Rlckluc3RhbmNlczogZGJDbHVzdGVySW5zdGFuY2VzLFxuICAgIH0pO1xuICAgIGNvbnN0IGtleWNsb2FrQ29udGFpbmVyU2VydmljZSA9IHRoaXMuYWRkS2V5Q2xvYWtDb250YWluZXJTZXJ2aWNlKHtcbiAgICAgIGRhdGFiYXNlOiB0aGlzLmRiLFxuICAgICAgdnBjOiB0aGlzLnZwYyxcbiAgICAgIGtleWNsb2FrVmVyc2lvbjogcHJvcHMua2V5Y2xvYWtWZXJzaW9uLFxuICAgICAgcHVibGljU3VibmV0czogcHJvcHMucHVibGljU3VibmV0cyxcbiAgICAgIHByaXZhdGVTdWJuZXRzOiBwcm9wcy5wcml2YXRlU3VibmV0cyxcbiAgICAgIGtleWNsb2FrU2VjcmV0OiB0aGlzLmtleWNsb2FrU2VjcmV0LFxuICAgICAgY2VydGlmaWNhdGU6IGNlcnRtZ3IuQ2VydGlmaWNhdGUuZnJvbUNlcnRpZmljYXRlQXJuKHRoaXMsICdBQ01DZXJ0JywgcHJvcHMuY2VydGlmaWNhdGVBcm4pLFxuICAgICAgYmFzdGlvbjogcHJvcHMuYmFzdGlvbixcbiAgICAgIG5vZGVDb3VudDogcHJvcHMubm9kZUNvdW50LFxuICAgICAgc3RpY2tpbmVzc0Nvb2tpZUR1cmF0aW9uOiBwcm9wcy5zdGlja2luZXNzQ29va2llRHVyYXRpb24sXG4gICAgICBhdXRvU2NhbGVUYXNrOiBwcm9wcy5hdXRvU2NhbGVUYXNrLFxuICAgICAgZW52OiBwcm9wcy5lbnYsXG4gICAgICBpbnRlcm5ldEZhY2luZzogcHJvcHMuaW50ZXJuZXRGYWNpbmcgPz8gdHJ1ZSxcbiAgICAgIGhvc3RuYW1lOiBwcm9wcy5ob3N0bmFtZSxcbiAgICAgIGNvbnRhaW5lckltYWdlOiBwcm9wcy5jb250YWluZXJJbWFnZSxcbiAgICAgIGNwdSxcbiAgICAgIG1lbW9yeUxpbWl0TWlCLFxuICAgIH0pO1xuXG4gICAgdGhpcy5hcHBsaWNhdGlvbkxvYWRCYWxhbmNlciA9IGtleWNsb2FrQ29udGFpbmVyU2VydmljZS5hcHBsaWNhdGlvbkxvYWRCYWxhbmNlcjtcbiAgICAvLyB0aGlzLm5ldHdvcmtMb2FkQmFsYW5jZXIgPSBrZXljbG9ha0NvbnRhaW5lclNlcnZpY2UubmV0d29ya0xvYWRCYWxhbmNlcjtcbiAgICBpZiAoIWNkay5TdGFjay5vZih0aGlzKS50ZW1wbGF0ZU9wdGlvbnMuZGVzY3JpcHRpb24pIHtcbiAgICAgIGNkay5TdGFjay5vZih0aGlzKS50ZW1wbGF0ZU9wdGlvbnMuZGVzY3JpcHRpb24gPSAnKFNPODAyMSkgLSBEZXBsb3kga2V5Y2xvYWsgb24gQVdTIHdpdGggY2RrLWtleWNsb2FrIGNvbnN0cnVjdCBsaWJyYXJ5JztcbiAgICB9XG4gIH1cbiAgcHVibGljIGFkZERhdGFiYXNlKHByb3BzOiBEYXRhYmFzZVByb3BzKTogRGF0YWJhc2Uge1xuICAgIHJldHVybiBuZXcgRGF0YWJhc2UodGhpcywgJ0RhdGFiYXNlJywgcHJvcHMpO1xuICB9XG4gIHB1YmxpYyBhZGRLZXlDbG9ha0NvbnRhaW5lclNlcnZpY2UocHJvcHM6IENvbnRhaW5lclNlcnZpY2VQcm9wcykge1xuICAgIHJldHVybiBuZXcgQ29udGFpbmVyU2VydmljZSh0aGlzLCAnS2V5Q2xvYWtDb250YWluZXJTZXJpdmNlJywgcHJvcHMpO1xuICB9XG4gIHByaXZhdGUgX2dlbmVyYXRlS2V5Y2xvYWtTZWNyZXQoKTogc2VjcmV0c21hbmFnZXIuSVNlY3JldCB7XG4gICAgcmV0dXJuIG5ldyBzZWNyZXRzbWFuYWdlci5TZWNyZXQodGhpcywgJ0tDU2VjcmV0Jywge1xuICAgICAgZ2VuZXJhdGVTZWNyZXRTdHJpbmc6IHtcbiAgICAgICAgZ2VuZXJhdGVTdHJpbmdLZXk6ICdwYXNzd29yZCcsXG4gICAgICAgIGV4Y2x1ZGVQdW5jdHVhdGlvbjogdHJ1ZSxcbiAgICAgICAgcGFzc3dvcmRMZW5ndGg6IDEyLFxuICAgICAgICBzZWNyZXRTdHJpbmdUZW1wbGF0ZTogSlNPTi5zdHJpbmdpZnkoeyB1c2VybmFtZTogJ2tleWNsb2FrJyB9KSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cbn1cblxuZXhwb3J0IGludGVyZmFjZSBEYXRhYmFzZVByb3BzIHtcbiAgLyoqXG4gICAqIFRoZSBWUEMgZm9yIHRoZSBkYXRhYmFzZVxuICAgKi9cbiAgcmVhZG9ubHkgdnBjOiBlYzIuSVZwYztcbiAgLyoqXG4gICAqIFZQQyBzdWJuZXRzIGZvciBkYXRhYmFzZVxuICAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2VTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBpbnN0YW5jZSB0eXBlXG4gICAqXG4gICAqIEBkZWZhdWx0IHI1LmxhcmdlXG4gICAqL1xuICByZWFkb25seSBpbnN0YW5jZVR5cGU/OiBlYzIuSW5zdGFuY2VUeXBlO1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGluc3RhbmNlIGVuZ2luZVxuICAgKlxuICAgKiBAZGVmYXVsdCAtIE15U1FMIDguMC4yMVxuICAgKi9cbiAgcmVhZG9ubHkgaW5zdGFuY2VFbmdpbmU/OiByZHMuSUluc3RhbmNlRW5naW5lO1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGNsdXN0ZXIgZW5naW5lXG4gICAqXG4gICAqIEBkZWZhdWx0IHJkcy5BdXJvcmFNeXNxbEVuZ2luZVZlcnNpb24uVkVSXzJfMDlfMVxuICAgKi9cbiAgcmVhZG9ubHkgY2x1c3RlckVuZ2luZT86IHJkcy5JQ2x1c3RlckVuZ2luZTtcbiAgLyoqXG4gICAqIGVuYWJsZSBhdXJvcmEgc2VydmVybGVzc1xuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYXVyb3JhU2VydmVybGVzcz86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBlbmFibGUgYXVyb3JhIHNlcnZlcmxlc3MgdjJcbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGF1cm9yYVNlcnZlcmxlc3NWMj86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gdXNlIHNpbmdsZSBSRFMgaW5zdGFuY2UgcmF0aGVyIHRoYW4gUkRTIGNsdXN0ZXIuIE5vdCByZWNvbW1lbmRlZCBmb3IgcHJvZHVjdGlvbi5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IHNpbmdsZURiSW5zdGFuY2U/OiBib29sZWFuO1xuICAvKipcbiAgICogZGF0YWJhc2UgYmFja3VwIHJldGVuc2lvblxuICAgKlxuICAgKiBAZGVmYXVsdCAtIDcgZGF5c1xuICAgKi9cbiAgcmVhZG9ubHkgYmFja3VwUmV0ZW50aW9uPzogY2RrLkR1cmF0aW9uO1xuICAvKipcbiAgICogVGhlIG1pbmltdW0gbnVtYmVyIG9mIEF1cm9yYSBTZXJ2ZXJsZXNzIFYyIGNhcGFjaXR5IHVuaXRzLlxuICAgKlxuICAgKiBAZGVmYXVsdCAwLjVcbiAgKi9cbiAgcmVhZG9ubHkgbWluQ2FwYWNpdHk/OiBudW1iZXI7XG4gIC8qKlxuICAgKiBUaGUgbWF4aW11bSBudW1iZXIgb2YgQXVyb3JhIFNlcnZlcmxlc3MgVjIgY2FwYWNpdHkgdW5pdHMuXG4gICAqXG4gICAqIEBkZWZhdWx0IDEwXG4gICAqL1xuICByZWFkb25seSBtYXhDYXBhY2l0eT86IG51bWJlcjtcblxuICAvKipcbiAgICogQ29udHJvbHMgd2hhdCBoYXBwZW5zIHRvIHRoZSBkYXRhYmFzZSBpZiBpdCBzdG9wcyBiZWluZyBtYW5hZ2VkIGJ5IENsb3VkRm9ybWF0aW9uXG4gICAqXG4gICAqIEBkZWZhdWx0IFJlbW92YWxQb2xpY3kuUkVUQUlOXG4gICAqL1xuICByZWFkb25seSByZW1vdmFsUG9saWN5PzogY2RrLlJlbW92YWxQb2xpY3k7XG5cbiAgLyoqXG4gICAqIE51bWJlciBvZiBpbnN0YW5jZXMgdG8gc3Bhd24gaW4gdGhlIGRhdGFiYXNlIGNsdXN0ZXIgKGZvciBjbHVzdGVyIGRhdGFiYXNlIG9wdGlvbnMgb25seSkuXG4gICAqXG4gICAqIEBkZWZhdWx0IDJcbiAgICovXG4gIHJlYWRvbmx5IGRiQ2x1c3Rlckluc3RhbmNlcz86IG51bWJlcjtcbn1cblxuLyoqXG4gKiBEYXRhYmFzZSBjb25maWd1cmF0aW9uXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgRGF0YWJhc2VDb25maWcge1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIHNlY3JldC5cbiAgICovXG4gIHJlYWRvbmx5IHNlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBjb25ubmVjdGlvbnMuXG4gICAqL1xuICByZWFkb25seSBjb25uZWN0aW9uczogZWMyLkNvbm5lY3Rpb25zO1xuICAvKipcbiAgICogVGhlIGVuZHBvaW50IGFkZHJlc3MgZm9yIHRoZSBkYXRhYmFzZS5cbiAgICovXG4gIHJlYWRvbmx5IGVuZHBvaW50OiBzdHJpbmc7XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2FlIGlkZW50aWZpZXIuXG4gICAqL1xuICByZWFkb25seSBpZGVudGlmaWVyOiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyB0aGUgZGF0YWJhc2UgaW5zdGFuY2Ugb3IgZGF0YWJhc2UgY2x1c3RlclxuICovXG5leHBvcnQgY2xhc3MgRGF0YWJhc2UgZXh0ZW5kcyBDb25zdHJ1Y3Qge1xuICByZWFkb25seSB2cGM6IGVjMi5JVnBjO1xuICByZWFkb25seSBjbHVzdGVyRW5kcG9pbnRIb3N0bmFtZTogc3RyaW5nO1xuICByZWFkb25seSBjbHVzdGVySWRlbnRpZmllcjogc3RyaW5nO1xuICByZWFkb25seSBzZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIHJlYWRvbmx5IGNvbm5lY3Rpb25zOiBlYzIuQ29ubmVjdGlvbnM7XG4gIHByaXZhdGUgcmVhZG9ubHkgX215c3FsTGlzdGVuZXJQb3J0OiBudW1iZXIgPSAzMzA2O1xuXG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBEYXRhYmFzZVByb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkKTtcbiAgICB0aGlzLnZwYyA9IHByb3BzLnZwYztcbiAgICBsZXQgY29uZmlnO1xuICAgIGlmIChwcm9wcy5hdXJvcmFTZXJ2ZXJsZXNzKSB7XG4gICAgICBjb25maWcgPSB0aGlzLl9jcmVhdGVTZXJ2ZXJsZXNzQ2x1c3Rlcihwcm9wcyk7XG4gICAgfSBlbHNlIGlmIChwcm9wcy5hdXJvcmFTZXJ2ZXJsZXNzVjIpIHtcbiAgICAgIGNvbmZpZyA9IHRoaXMuX2NyZWF0ZVNlcnZlcmxlc3NWMkNsdXN0ZXIocHJvcHMpO1xuICAgIH0gZWxzZSBpZiAocHJvcHMuc2luZ2xlRGJJbnN0YW5jZSkge1xuICAgICAgY29uZmlnID0gdGhpcy5fY3JlYXRlUmRzSW5zdGFuY2UocHJvcHMpO1xuICAgIH0gZWxzZSB7XG4gICAgICBjb25maWcgPSB0aGlzLl9jcmVhdGVSZHNDbHVzdGVyKHByb3BzKTtcbiAgICB9XG4gICAgdGhpcy5zZWNyZXQgPSBjb25maWcuc2VjcmV0O1xuICAgIC8vIGFsbG93IGludGVybmFsbHkgZnJvbSB0aGUgc2FtZSBzZWN1cml0eSBncm91cFxuICAgIGNvbmZpZy5jb25uZWN0aW9ucy5hbGxvd0ludGVybmFsbHkoZWMyLlBvcnQudGNwKHRoaXMuX215c3FsTGlzdGVuZXJQb3J0KSk7XG4gICAgLy8gYWxsb3cgZnJvbSB0aGUgd2hvbGUgdnBjIGNpZHJcbiAgICBjb25maWcuY29ubmVjdGlvbnMuYWxsb3dGcm9tKGVjMi5QZWVyLmlwdjQocHJvcHMudnBjLnZwY0NpZHJCbG9jayksIGVjMi5Qb3J0LnRjcCh0aGlzLl9teXNxbExpc3RlbmVyUG9ydCkpO1xuICAgIHRoaXMuY2x1c3RlckVuZHBvaW50SG9zdG5hbWUgPSBjb25maWcuZW5kcG9pbnQ7XG4gICAgdGhpcy5jbHVzdGVySWRlbnRpZmllciA9IGNvbmZpZy5pZGVudGlmaWVyO1xuICAgIHRoaXMuY29ubmVjdGlvbnMgPSBjb25maWcuY29ubmVjdGlvbnM7XG4gICAgcHJpbnRPdXRwdXQodGhpcywgJ0RCU2VjcmV0QXJuJywgY29uZmlnLnNlY3JldC5zZWNyZXRBcm4pO1xuICAgIHByaW50T3V0cHV0KHRoaXMsICdjbHVzdGVyRW5kcG9pbnRIb3N0bmFtZScsIHRoaXMuY2x1c3RlckVuZHBvaW50SG9zdG5hbWUpO1xuICAgIHByaW50T3V0cHV0KHRoaXMsICdjbHVzdGVySWRlbnRpZmllcicsIHRoaXMuY2x1c3RlcklkZW50aWZpZXIpO1xuICB9XG4gIHByaXZhdGUgX2NyZWF0ZVJkc0luc3RhbmNlKHByb3BzOiBEYXRhYmFzZVByb3BzKTogRGF0YWJhc2VDb25maWcge1xuICAgIGNvbnN0IGRiSW5zdGFuY2UgPSBuZXcgcmRzLkRhdGFiYXNlSW5zdGFuY2UodGhpcywgJ0RCSW5zdGFuY2UnLCB7XG4gICAgICB2cGM6IHByb3BzLnZwYyxcbiAgICAgIGRhdGFiYXNlTmFtZTogJ2tleWNsb2FrJyxcbiAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgIGVuZ2luZTogcHJvcHMuaW5zdGFuY2VFbmdpbmUgPz8gcmRzLkRhdGFiYXNlSW5zdGFuY2VFbmdpbmUubXlzcWwoe1xuICAgICAgICB2ZXJzaW9uOiByZHMuTXlzcWxFbmdpbmVWZXJzaW9uLlZFUl84XzBfMjEsXG4gICAgICB9KSxcbiAgICAgIHN0b3JhZ2VFbmNyeXB0ZWQ6IHRydWUsXG4gICAgICBiYWNrdXBSZXRlbnRpb246IHByb3BzLmJhY2t1cFJldGVudGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cyg3KSxcbiAgICAgIGNyZWRlbnRpYWxzOiByZHMuQ3JlZGVudGlhbHMuZnJvbUdlbmVyYXRlZFNlY3JldCgnYWRtaW4nKSxcbiAgICAgIGluc3RhbmNlVHlwZTogcHJvcHMuaW5zdGFuY2VUeXBlID8/IG5ldyBlYzIuSW5zdGFuY2VUeXBlKCdyNS5sYXJnZScpLFxuICAgICAgcGFyYW1ldGVyR3JvdXA6IHJkcy5QYXJhbWV0ZXJHcm91cC5mcm9tUGFyYW1ldGVyR3JvdXBOYW1lKHRoaXMsICdQYXJhbWV0ZXJHcm91cCcsICdkZWZhdWx0Lm15c3FsOC4wJyksXG4gICAgICBkZWxldGlvblByb3RlY3Rpb246IGZhbHNlLFxuICAgICAgcmVtb3ZhbFBvbGljeTogcHJvcHMucmVtb3ZhbFBvbGljeSA/PyBjZGsuUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgfSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGNvbm5lY3Rpb25zOiBkYkluc3RhbmNlLmNvbm5lY3Rpb25zLFxuICAgICAgZW5kcG9pbnQ6IGRiSW5zdGFuY2UuZGJJbnN0YW5jZUVuZHBvaW50QWRkcmVzcyxcbiAgICAgIGlkZW50aWZpZXI6IGRiSW5zdGFuY2UuaW5zdGFuY2VJZGVudGlmaWVyLFxuICAgICAgc2VjcmV0OiBkYkluc3RhbmNlLnNlY3JldCEsXG4gICAgfTtcbiAgfVxuICAvLyBjcmVhdGUgYSBSRFMgZm9yIE15U1FMIERCIGNsdXN0ZXJcbiAgcHJpdmF0ZSBfY3JlYXRlUmRzQ2x1c3Rlcihwcm9wczogRGF0YWJhc2VQcm9wcyk6IERhdGFiYXNlQ29uZmlnIHtcbiAgICBjb25zdCBkYkNsdXN0ZXIgPSBuZXcgcmRzLkRhdGFiYXNlQ2x1c3Rlcih0aGlzLCAnREJDbHVzdGVyJywge1xuICAgICAgZW5naW5lOiBwcm9wcy5jbHVzdGVyRW5naW5lID8/IHJkcy5EYXRhYmFzZUNsdXN0ZXJFbmdpbmUuYXVyb3JhTXlzcWwoe1xuICAgICAgICB2ZXJzaW9uOiByZHMuQXVyb3JhTXlzcWxFbmdpbmVWZXJzaW9uLlZFUl8yXzA5XzEsXG4gICAgICB9KSxcbiAgICAgIGluc3RhbmNlczogcHJvcHMuZGJDbHVzdGVySW5zdGFuY2VzID8/IDIsXG4gICAgICBkZWZhdWx0RGF0YWJhc2VOYW1lOiAna2V5Y2xvYWsnLFxuICAgICAgZGVsZXRpb25Qcm90ZWN0aW9uOiBmYWxzZSxcbiAgICAgIGNyZWRlbnRpYWxzOiByZHMuQ3JlZGVudGlhbHMuZnJvbUdlbmVyYXRlZFNlY3JldCgnYWRtaW4nKSxcbiAgICAgIGluc3RhbmNlUHJvcHM6IHtcbiAgICAgICAgdnBjOiBwcm9wcy52cGMsXG4gICAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgICAgaW5zdGFuY2VUeXBlOiBwcm9wcy5pbnN0YW5jZVR5cGUgPz8gbmV3IGVjMi5JbnN0YW5jZVR5cGUoJ3I1LmxhcmdlJyksXG4gICAgICB9LFxuICAgICAgcGFyYW1ldGVyR3JvdXA6IHJkcy5QYXJhbWV0ZXJHcm91cC5mcm9tUGFyYW1ldGVyR3JvdXBOYW1lKHRoaXMsICdQYXJhbWV0ZXJHcm91cCcsICdkZWZhdWx0LmF1cm9yYS1teXNxbDguMCcpLFxuICAgICAgYmFja3VwOiB7XG4gICAgICAgIHJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uID8/IGNkay5EdXJhdGlvbi5kYXlzKDcpLFxuICAgICAgfSxcbiAgICAgIHN0b3JhZ2VFbmNyeXB0ZWQ6IHRydWUsXG4gICAgICByZW1vdmFsUG9saWN5OiBwcm9wcy5yZW1vdmFsUG9saWN5ID8/IGNkay5SZW1vdmFsUG9saWN5LlJFVEFJTixcbiAgICB9KTtcbiAgICByZXR1cm4ge1xuICAgICAgY29ubmVjdGlvbnM6IGRiQ2x1c3Rlci5jb25uZWN0aW9ucyxcbiAgICAgIGVuZHBvaW50OiBkYkNsdXN0ZXIuY2x1c3RlckVuZHBvaW50Lmhvc3RuYW1lLFxuICAgICAgaWRlbnRpZmllcjogZGJDbHVzdGVyLmNsdXN0ZXJJZGVudGlmaWVyLFxuICAgICAgc2VjcmV0OiBkYkNsdXN0ZXIuc2VjcmV0ISxcbiAgICB9O1xuICB9XG4gIHByaXZhdGUgX2NyZWF0ZVNlcnZlcmxlc3NDbHVzdGVyKHByb3BzOiBEYXRhYmFzZVByb3BzKTogRGF0YWJhc2VDb25maWcge1xuICAgIGNvbnN0IGRiQ2x1c3RlciA9IG5ldyByZHMuU2VydmVybGVzc0NsdXN0ZXIodGhpcywgJ0F1cm9yYVNlcnZlcmxlc3NDbHVzdGVyJywge1xuICAgICAgZW5naW5lOiByZHMuRGF0YWJhc2VDbHVzdGVyRW5naW5lLkFVUk9SQV9NWVNRTCxcbiAgICAgIHZwYzogcHJvcHMudnBjLFxuICAgICAgZGVmYXVsdERhdGFiYXNlTmFtZTogJ2tleWNsb2FrJyxcbiAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgIGNyZWRlbnRpYWxzOiByZHMuQ3JlZGVudGlhbHMuZnJvbUdlbmVyYXRlZFNlY3JldCgnYWRtaW4nKSxcbiAgICAgIGJhY2t1cFJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uID8/IGNkay5EdXJhdGlvbi5kYXlzKDcpLFxuICAgICAgZGVsZXRpb25Qcm90ZWN0aW9uOiBmYWxzZSxcbiAgICAgIHJlbW92YWxQb2xpY3k6IHByb3BzLnJlbW92YWxQb2xpY3kgPz8gY2RrLlJlbW92YWxQb2xpY3kuUkVUQUlOLFxuICAgICAgcGFyYW1ldGVyR3JvdXA6IHJkcy5QYXJhbWV0ZXJHcm91cC5mcm9tUGFyYW1ldGVyR3JvdXBOYW1lKHRoaXMsICdQYXJhbWV0ZXJHcm91cCcsICdkZWZhdWx0LmF1cm9yYS1teXNxbDguMCcpLFxuICAgIH0pO1xuICAgIHJldHVybiB7XG4gICAgICBjb25uZWN0aW9uczogZGJDbHVzdGVyLmNvbm5lY3Rpb25zLFxuICAgICAgZW5kcG9pbnQ6IGRiQ2x1c3Rlci5jbHVzdGVyRW5kcG9pbnQuaG9zdG5hbWUsXG4gICAgICBpZGVudGlmaWVyOiBkYkNsdXN0ZXIuY2x1c3RlcklkZW50aWZpZXIsXG4gICAgICBzZWNyZXQ6IGRiQ2x1c3Rlci5zZWNyZXQhLFxuICAgIH07XG4gIH1cbiAgLy8gY3JlYXRlIGEgUkRTIGZvciBNeVNRTCBEQiBjbHVzdGVyIHdpdGggQXVyb3JhIFNlcnZlcmxlc3MgdjJcbiAgcHJpdmF0ZSBfY3JlYXRlU2VydmVybGVzc1YyQ2x1c3Rlcihwcm9wczogRGF0YWJhc2VQcm9wcyk6IERhdGFiYXNlQ29uZmlnIHtcbiAgICBjb25zdCBkYkNsdXN0ZXIgPSBuZXcgcmRzLkRhdGFiYXNlQ2x1c3Rlcih0aGlzLCAnREJDbHVzdGVyJywge1xuICAgICAgZW5naW5lOiBwcm9wcy5jbHVzdGVyRW5naW5lID8/IHJkcy5EYXRhYmFzZUNsdXN0ZXJFbmdpbmUuYXVyb3JhTXlzcWwoe1xuICAgICAgICB2ZXJzaW9uOiByZHMuQXVyb3JhTXlzcWxFbmdpbmVWZXJzaW9uLlZFUl8zXzAyXzAsXG4gICAgICB9KSxcbiAgICAgIGluc3RhbmNlczogcHJvcHMuZGJDbHVzdGVySW5zdGFuY2VzID8/IDIsXG4gICAgICBkZWZhdWx0RGF0YWJhc2VOYW1lOiAna2V5Y2xvYWsnLFxuICAgICAgZGVsZXRpb25Qcm90ZWN0aW9uOiBmYWxzZSxcbiAgICAgIGNyZWRlbnRpYWxzOiByZHMuQ3JlZGVudGlhbHMuZnJvbUdlbmVyYXRlZFNlY3JldCgnYWRtaW4nKSxcbiAgICAgIGluc3RhbmNlUHJvcHM6IHtcbiAgICAgICAgdnBjOiBwcm9wcy52cGMsXG4gICAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgICAgLy8gU3BlY2lmeSBzZXJ2ZXJsZXNzIEluc3RhbmNlIFR5cGVcbiAgICAgICAgaW5zdGFuY2VUeXBlOiBuZXcgZWMyLkluc3RhbmNlVHlwZSgnc2VydmVybGVzcycpLFxuICAgICAgfSxcbiAgICAgIC8vIFNldCBkZWZhdWx0IHBhcmFtZXRlciBncm91cCBmb3IgQXVyb3JhIE15U1FMIDguMFxuICAgICAgcGFyYW1ldGVyR3JvdXA6IHJkcy5QYXJhbWV0ZXJHcm91cC5mcm9tUGFyYW1ldGVyR3JvdXBOYW1lKHRoaXMsICdQYXJhbWV0ZXJHcm91cCcsICdkZWZhdWx0LmF1cm9yYS1teXNxbDguMCcpLFxuICAgICAgYmFja3VwOiB7XG4gICAgICAgIHJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uID8/IGNkay5EdXJhdGlvbi5kYXlzKDcpLFxuICAgICAgfSxcbiAgICAgIHN0b3JhZ2VFbmNyeXB0ZWQ6IHRydWUsXG4gICAgICByZW1vdmFsUG9saWN5OiBwcm9wcy5yZW1vdmFsUG9saWN5ID8/IGNkay5SZW1vdmFsUG9saWN5LlJFVEFJTixcbiAgICB9KTtcbiAgICAvLyBTZXQgU2VydmVybGVzcyBWMiBTY2FsaW5nIENvbmZpZ3VyYXRpb25cbiAgICAvLyBUT0RPOiBVc2UgY2xlYW5lciB3YXkgdG8gc2V0IHNjYWxpbmcgY29uZmlndXJhdGlvbi5cbiAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vYXdzL2F3cy1jZGsvaXNzdWVzLzIwMTk3XG4gICAgKFxuICAgICAgZGJDbHVzdGVyLm5vZGUuZmluZENoaWxkKCdSZXNvdXJjZScpIGFzIHJkcy5DZm5EQkNsdXN0ZXJcbiAgICApLnNlcnZlcmxlc3NWMlNjYWxpbmdDb25maWd1cmF0aW9uID0ge1xuICAgICAgbWluQ2FwYWNpdHk6IHByb3BzLm1pbkNhcGFjaXR5ID8/IDAuNSxcbiAgICAgIG1heENhcGFjaXR5OiBwcm9wcy5tYXhDYXBhY2l0eSA/PyAxMCxcbiAgICB9O1xuICAgIHJldHVybiB7XG4gICAgICBjb25uZWN0aW9uczogZGJDbHVzdGVyLmNvbm5lY3Rpb25zLFxuICAgICAgZW5kcG9pbnQ6IGRiQ2x1c3Rlci5jbHVzdGVyRW5kcG9pbnQuaG9zdG5hbWUsXG4gICAgICBpZGVudGlmaWVyOiBkYkNsdXN0ZXIuY2x1c3RlcklkZW50aWZpZXIsXG4gICAgICBzZWNyZXQ6IGRiQ2x1c3Rlci5zZWNyZXQhLFxuICAgIH07XG4gIH1cbn1cblxuZXhwb3J0IGludGVyZmFjZSBDb250YWluZXJTZXJ2aWNlUHJvcHMge1xuICAvKipcbiAgICogVGhlIGVudmlyb25tZW50IHZhcmlhYmxlcyB0byBwYXNzIHRvIHRoZSBrZXljbG9hayBjb250YWluZXJcbiAgICovXG4gIHJlYWRvbmx5IGVudj86IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIH07XG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIGZvciB0aGUgY29udGFpbmVyIGltYWdlXG4gICAqL1xuICByZWFkb25seSBrZXljbG9ha1ZlcnNpb246IEtleWNsb2FrVmVyc2lvbjtcbiAgLyoqXG4gICAqIFRoZSBWUEMgZm9yIHRoZSBzZXJ2aWNlXG4gICAqL1xuICByZWFkb25seSB2cGM6IGVjMi5JVnBjO1xuICAvKipcbiAgICogVlBDIHN1Ym5ldHMgZm9yIGtleWNsb2FrIHNlcnZpY2VcbiAgICovXG4gIHJlYWRvbmx5IHByaXZhdGVTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFZQQyBwdWJsaWMgc3VibmV0cyBmb3IgQUxCXG4gICAqL1xuICByZWFkb25seSBwdWJsaWNTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFRoZSBSRFMgZGF0YWJhc2UgZm9yIHRoZSBzZXJ2aWNlXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZTogRGF0YWJhc2U7XG4gIC8qKlxuICAgKiBUaGUgc2VjcmV0cyBtYW5hZ2VyIHNlY3JldCBmb3IgdGhlIGtleWNsb2FrXG4gICAqL1xuICByZWFkb25seSBrZXljbG9ha1NlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgLyoqXG4gICAqIFRoZSBBQ00gY2VydGlmaWNhdGVcbiAgICovXG4gIHJlYWRvbmx5IGNlcnRpZmljYXRlOiBjZXJ0bWdyLklDZXJ0aWZpY2F0ZTtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gY3JlYXRlIHRoZSBiYXN0aW9uIGhvc3RcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGJhc3Rpb24/OiBib29sZWFuO1xuICAvKipcbiAgICogV2hldGhlciB0byBlbmFibGUgdGhlIEVDUyBzZXJ2aWNlIGRlcGxveW1lbnQgY2lyY3VpdCBicmVha2VyXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBjaXJjdWl0QnJlYWtlcj86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBOdW1iZXIgb2Yga2V5Y2xvYWsgbm9kZSBpbiB0aGUgY2x1c3RlclxuICAgKlxuICAgKiBAZGVmYXVsdCAxXG4gICAqL1xuICByZWFkb25seSBub2RlQ291bnQ/OiBudW1iZXI7XG4gIC8qKlxuICAgKiBUaGUgc3RpY2t5IHNlc3Npb24gZHVyYXRpb24gZm9yIHRoZSBrZXljbG9hayB3b3JrbG9hZCB3aXRoIEFMQi5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBvbmUgZGF5XG4gICAqL1xuICByZWFkb25seSBzdGlja2luZXNzQ29va2llRHVyYXRpb24/OiBjZGsuRHVyYXRpb247XG5cbiAgLyoqXG4gICAqIEF1dG9zY2FsaW5nIGZvciB0aGUgRUNTIFNlcnZpY2VcbiAgICpcbiAgICogQGRlZmF1bHQgLSBubyBlY3Mgc2VydmljZSBhdXRvc2NhbGluZ1xuICAgKi9cbiAgcmVhZG9ubHkgYXV0b1NjYWxlVGFzaz86IEF1dG9TY2FsZVRhc2s7XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gcHV0IHRoZSBwdXQgdGhlIGxvYWQgYmFsYW5jZXIgaW4gdGhlIHB1YmxpYyBvciBwcml2YXRlIHN1Ym5ldHNcbiAgICpcbiAgICogQGRlZmF1bHQgdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgaW50ZXJuZXRGYWNpbmc/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBUaGUgaG9zdG5hbWUgdG8gdXNlIGZvciB0aGUga2V5Y2xvYWsgc2VydmVyXG4gICAqL1xuICByZWFkb25seSBob3N0bmFtZT86IHN0cmluZztcblxuXG4gIC8qKlxuICAgKiBPdmVycmlkZXMgdGhlIGRlZmF1bHQgaW1hZ2VcbiAgICpcbiAgICogQGRlZmF1bHQgcXVheS5pby9rZXljbG9hay9rZXljbG9hazoke0tFWUNMT0FLX1ZFUlNJT059XG4gICAqL1xuICByZWFkb25seSBjb250YWluZXJJbWFnZT86IGVjcy5Db250YWluZXJJbWFnZTtcblxuICAvKipcbiAgICogVGhlIG51bWJlciBvZiBjcHUgdW5pdHMgdXNlZCBieSB0aGUgS2V5Y2xvYWsgdGFzay5cbiAgICogWW91IG11c3QgdXNlIG9uZSBvZiB0aGUgZm9sbG93aW5nIHZhbHVlcywgd2hpY2ggZGV0ZXJtaW5lcyB5b3VyIHJhbmdlIG9mIHZhbGlkIHZhbHVlcyBmb3IgdGhlIG1lbW9yeSBwYXJhbWV0ZXI6XG4gICAqIDI1NiAoLjI1IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IDUxMiAoMC41IEdCKSwgMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpXG4gICAqIDUxMiAoLjUgdkNQVSkgLSBBdmFpbGFibGUgbWVtb3J5IHZhbHVlczogMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpLCAzMDcyICgzIEdCKSwgNDA5NiAoNCBHQilcbiAgICogMTAyNCAoMSB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpLCA1MTIwICg1IEdCKSwgNjE0NCAoNiBHQiksIDcxNjggKDcgR0IpLCA4MTkyICg4IEdCKVxuICAgKiAyMDQ4ICgyIHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gNDA5NiAoNCBHQikgYW5kIDE2Mzg0ICgxNiBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKVxuICAgKiA0MDk2ICg0IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gODE5MiAoOCBHQikgYW5kIDMwNzIwICgzMCBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKVxuICAgKiA4MTkyICg4IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gMTYzODQgKDE2IEdCKSBhbmQgNjE0NDAgKDYwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDQwOTYgKDQgR0IpXG4gICAqIDE2Mzg0ICgxNiB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiBCZXR3ZWVuIDMyNzY4ICgzMiBHQikgYW5kIDEyMjg4MCAoMTIwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDgxOTIgKDggR0IpXG4gICAqL1xuICByZWFkb25seSBjcHU6IG51bWJlcjtcblxuICAvKipcbiAgICogVGhlIGFtb3VudCAoaW4gTWlCKSBvZiBtZW1vcnkgdXNlZCBieSB0aGUgdGFzay5cbiAgICogWW91IG11c3QgdXNlIG9uZSBvZiB0aGUgZm9sbG93aW5nIHZhbHVlcywgd2hpY2ggZGV0ZXJtaW5lcyB5b3VyIHJhbmdlIG9mIHZhbGlkIHZhbHVlcyBmb3IgdGhlIGNwdSBwYXJhbWV0ZXI6XG4gICAqIDUxMiAoMC41IEdCKSwgMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDI1NiAoLjI1IHZDUFUpXG4gICAqIDEwMjQgKDEgR0IpLCAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDUxMiAoLjUgdkNQVSlcbiAgICogMjA0OCAoMiBHQiksIDMwNzIgKDMgR0IpLCA0MDk2ICg0IEdCKSwgNTEyMCAoNSBHQiksIDYxNDQgKDYgR0IpLCA3MTY4ICg3IEdCKSwgODE5MiAoOCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMTAyNCAoMSB2Q1BVKVxuICAgKiBCZXR3ZWVuIDQwOTYgKDQgR0IpIGFuZCAxNjM4NCAoMTYgR0IpIGluIGluY3JlbWVudHMgb2YgMTAyNCAoMSBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMjA0OCAoMiB2Q1BVKVxuICAgKiBCZXR3ZWVuIDgxOTIgKDggR0IpIGFuZCAzMDcyMCAoMzAgR0IpIGluIGluY3JlbWVudHMgb2YgMTAyNCAoMSBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogNDA5NiAoNCB2Q1BVKVxuICAgKiBCZXR3ZWVuIDE2Mzg0ICgxNiBHQikgYW5kIDYxNDQwICg2MCBHQikgaW4gaW5jcmVtZW50cyBvZiA0MDk2ICg0IEdCKSAtIEF2YWlsYWJsZSBjcHUgdmFsdWVzOiA4MTkyICg4IHZDUFUpXG4gICAqIEJldHdlZW4gMzI3NjggKDMyIEdCKSBhbmQgMTIyODgwICgxMjAgR0IpIGluIGluY3JlbWVudHMgb2YgODE5MiAoOCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMTYzODQgKDE2IHZDUFUpXG4gICAqL1xuICByZWFkb25seSBtZW1vcnlMaW1pdE1pQjogbnVtYmVyO1xufVxuXG5leHBvcnQgY2xhc3MgQ29udGFpbmVyU2VydmljZSBleHRlbmRzIENvbnN0cnVjdCB7XG4gIHJlYWRvbmx5IHNlcnZpY2U6IGVjcy5GYXJnYXRlU2VydmljZTtcbiAgcmVhZG9ubHkgYXBwbGljYXRpb25Mb2FkQmFsYW5jZXI6IGVsYnYyLkFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyO1xuICAvLyByZWFkb25seSBuZXR3b3JrTG9hZEJhbGFuY2VyOiBlbGJ2Mi5OZXR3b3JrTG9hZEJhbGFuY2VyO1xuICByZWFkb25seSBrZXljbG9ha1VzZXJTZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBDb250YWluZXJTZXJ2aWNlUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQpO1xuXG4gICAgY29uc3QgeyBjcHUsIG1lbW9yeUxpbWl0TWlCIH0gPSBwcm9wcztcblxuICAgIGNvbnN0IHJlZ2lvbiA9IGNkay5TdGFjay5vZih0aGlzKS5yZWdpb247XG4gICAgY29uc3QgY29udGFpbmVyUG9ydCA9IDgwODA7XG4gICAgY29uc3QgY29ubmVjdGlvblN0cmluZyA9IGBqZGJjOm15c3FsOi8vJHtwcm9wcy5kYXRhYmFzZS5jbHVzdGVyRW5kcG9pbnRIb3N0bmFtZX06MzMwNi9rZXljbG9ha2A7XG4gICAgLy8gY29uc3QgcHJvdG9jb2wgPSBlbGJ2Mi5BcHBsaWNhdGlvblByb3RvY29sLkhUVFA7XG4gICAgY29uc3QgZW50cnlQb2ludCA9IFsnL29wdC9rZXljbG9hay9iaW4va2Muc2gnLCAnc3RhcnQnLCAnLS1vcHRpbWl6ZWQnXTtcbiAgICBjb25zdCBzM1BpbmdCdWNrZXQgPSBuZXcgczMuQnVja2V0KHRoaXMsICdrZXljbG9ha19zM19waW5nJywgeyByZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5LkRFU1RST1kgfSk7XG4gICAgY29uc3QgaW1hZ2UgPSBwcm9wcy5jb250YWluZXJJbWFnZSA/PyBlY3MuQ29udGFpbmVySW1hZ2UuZnJvbVJlZ2lzdHJ5KHRoaXMuZ2V0S2V5Q2xvYWtEb2NrZXJJbWFnZVVyaShwcm9wcy5rZXljbG9ha1ZlcnNpb24udmVyc2lvbikpO1xuICAgIGNvbnN0IHNlY3JldHM6IHtba2V5OiBzdHJpbmddOiBjZGsuYXdzX2Vjcy5TZWNyZXR9ID0ge1xuICAgICAgS0NfREJfUEFTU1dPUkQ6IGVjcy5TZWNyZXQuZnJvbVNlY3JldHNNYW5hZ2VyKHByb3BzLmRhdGFiYXNlLnNlY3JldCwgJ3Bhc3N3b3JkJyksXG4gICAgICBLRVlDTE9BS19BRE1JTjogZWNzLlNlY3JldC5mcm9tU2VjcmV0c01hbmFnZXIocHJvcHMua2V5Y2xvYWtTZWNyZXQsICd1c2VybmFtZScpLFxuICAgICAgS0VZQ0xPQUtfQURNSU5fUEFTU1dPUkQ6IGVjcy5TZWNyZXQuZnJvbVNlY3JldHNNYW5hZ2VyKHByb3BzLmtleWNsb2FrU2VjcmV0LCAncGFzc3dvcmQnKSxcbiAgICB9O1xuICAgIGNvbnN0IHBvcnRNYXBwaW5nczogZWNzLlBvcnRNYXBwaW5nW10gPSBbXG4gICAgICB7IGNvbnRhaW5lclBvcnQ6IGNvbnRhaW5lclBvcnQgfSwgLy8gd2ViIHBvcnRcbiAgICAgIHsgY29udGFpbmVyUG9ydDogNzgwMCB9LCAvLyBqZ3JvdXBzLXMzXG4gICAgICB7IGNvbnRhaW5lclBvcnQ6IDU3ODAwIH0sIC8vIGpncm91cHMtczMtZmRcbiAgICBdO1xuICAgIGNvbnN0IHZwYyA9IHByb3BzLnZwYztcbiAgICBjb25zdCBjbHVzdGVyID0gbmV3IGVjcy5DbHVzdGVyKHRoaXMsICdDbHVzdGVyJywgeyB2cGMsIGNvbnRhaW5lckluc2lnaHRzOiB0cnVlIH0pO1xuICAgIGNsdXN0ZXIubm9kZS5hZGREZXBlbmRlbmN5KHByb3BzLmRhdGFiYXNlKTtcbiAgICBjb25zdCBleGVjdXRpb25Sb2xlID0gbmV3IGlhbS5Sb2xlKHRoaXMsICdUYXNrUm9sZScsIHtcbiAgICAgIGFzc3VtZWRCeTogbmV3IGlhbS5Db21wb3NpdGVQcmluY2lwYWwoXG4gICAgICAgIG5ldyBpYW0uU2VydmljZVByaW5jaXBhbCgnZWNzLmFtYXpvbmF3cy5jb20nKSxcbiAgICAgICAgbmV3IGlhbS5TZXJ2aWNlUHJpbmNpcGFsKCdlY3MtdGFza3MuYW1hem9uYXdzLmNvbScpLFxuICAgICAgKSxcbiAgICB9KTtcbiAgICBjb25zdCB0YXNrRGVmaW5pdGlvbiA9IG5ldyBlY3MuRmFyZ2F0ZVRhc2tEZWZpbml0aW9uKHRoaXMsICdUYXNrRGVmJywge1xuICAgICAgY3B1LFxuICAgICAgbWVtb3J5TGltaXRNaUIsXG4gICAgICBleGVjdXRpb25Sb2xlLFxuICAgIH0pO1xuXG4gICAgY29uc3QgbG9nR3JvdXAgPSBuZXcgbG9ncy5Mb2dHcm91cCh0aGlzLCAnTG9nR3JvdXAnLCB7XG4gICAgICByZXRlbnRpb246IGxvZ3MuUmV0ZW50aW9uRGF5cy5PTkVfTU9OVEgsXG4gICAgICByZW1vdmFsUG9saWN5OiBjZGsuUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgfSk7XG5cbiAgICBjb25zdCBzM1VzZXIgPSBuZXcgaWFtLlVzZXIodGhpcywgJ1MzS2V5Y2xvYWtVc2VyJyk7XG4gICAgY29uc3QgYWNjZXNzS2V5ID0gbmV3IGlhbS5BY2Nlc3NLZXkodGhpcywgJ1MzS2V5Y2xvYWtVc2VyQWNjZXNzS2V5JywgeyB1c2VyOiBzM1VzZXIgfSk7XG4gICAgdGhpcy5rZXljbG9ha1VzZXJTZWNyZXQgPSBuZXcgc2VjcmV0c21hbmFnZXIuU2VjcmV0KHRoaXMsICdTM0tleWNsb2FrVXNlclNlY3JldCcsIHtcbiAgICAgIHNlY3JldFN0cmluZ1ZhbHVlOiBhY2Nlc3NLZXkuc2VjcmV0QWNjZXNzS2V5LFxuICAgIH0pO1xuICAgIHMzUGluZ0J1Y2tldCEuZ3JhbnRSZWFkV3JpdGUoczNVc2VyKTtcblxuICAgIGNvbnN0IGVudmlyb25tZW50OiB7W2tleTogc3RyaW5nXTogc3RyaW5nfSA9IHtcbiAgICAgIEpBVkFfT1BUU19BUFBFTkQ6IGBcbiAgICAgIC1Eamdyb3Vwcy5zMy5yZWdpb25fbmFtZT0ke3JlZ2lvbn1cbiAgICAgIC1Eamdyb3Vwcy5zMy5idWNrZXRfbmFtZT0ke3MzUGluZ0J1Y2tldCEuYnVja2V0TmFtZX1cbiAgICAgIC1Eamdyb3Vwcy5zMy5hY2Nlc3Nfa2V5PSR7YWNjZXNzS2V5LmFjY2Vzc0tleUlkfVxuICAgICAgLURqZ3JvdXBzLnMzLnNlY3JldF9hY2Nlc3Nfa2V5PSR7YWNjZXNzS2V5LnNlY3JldEFjY2Vzc0tleX1cbiAgICAgIGAucmVwbGFjZSgnXFxyXFxuJywgJycpLnJlcGxhY2UoJ1xcbicsICcnKS5yZXBsYWNlKC9cXHMrL2csICcgJyksXG4gICAgICAvLyBXZSBoYXZlIHNlbGVjdGVkIHRoZSBjYWNoZSBzdGFjayBvZiAnZWMyJyB3aGljaCB1c2VzIFMzX1BJTkcgdW5kZXIgdGhlIGhvb2RcbiAgICAgIC8vIFRoaXMgaXMgdGhlIEFXUyBuYXRpdmUgY2x1c3RlciBkaXNjb3ZlcnkgYXBwcm9hY2ggZm9yIGNhY2hpbmdcbiAgICAgIC8vIFNlZTogaHR0cHM6Ly93d3cua2V5Y2xvYWsub3JnL3NlcnZlci9jYWNoaW5nI190cmFuc3BvcnRfc3RhY2tzXG4gICAgICBLQ19DQUNIRV9TVEFDSzogJ2VjMicsXG4gICAgICBLQ19EQjogJ215c3FsJyxcbiAgICAgIEtDX0RCX1VSTF9EQVRBQkFTRTogJ2tleWNsb2FrJyxcbiAgICAgIEtDX0RCX1VSTDogY29ubmVjdGlvblN0cmluZyxcbiAgICAgIEtDX0RCX1VSTF9QT1JUOiAnMzMwNicsXG4gICAgICBLQ19EQl9VU0VSTkFNRTogJ2FkbWluJyxcbiAgICAgIEtDX0hPU1ROQU1FOiBwcm9wcy5ob3N0bmFtZSEsXG4gICAgICBLQ19IT1NUTkFNRV9TVFJJQ1RfQkFDS0NIQU5ORUw6ICd0cnVlJyxcbiAgICAgIEtDX1BST1hZOiAnZWRnZScsXG4gICAgICBLQ19IRUFMVEhfRU5BQkxFRDogJ3RydWUnLFxuICAgIH07XG5cbiAgICBjb25zdCBrYyA9IHRhc2tEZWZpbml0aW9uLmFkZENvbnRhaW5lcigna2V5Y2xvYWsnLCB7XG4gICAgICBpbWFnZSxcbiAgICAgIGVudHJ5UG9pbnQsXG4gICAgICBlbnZpcm9ubWVudDogT2JqZWN0LmFzc2lnbihlbnZpcm9ubWVudCwgcHJvcHMuZW52KSxcbiAgICAgIHNlY3JldHMsXG4gICAgICBsb2dnaW5nOiBlY3MuTG9nRHJpdmVycy5hd3NMb2dzKHtcbiAgICAgICAgc3RyZWFtUHJlZml4OiAna2V5Y2xvYWsnLFxuICAgICAgICBsb2dHcm91cCxcbiAgICAgIH0pLFxuICAgIH0pO1xuICAgIGtjLmFkZFBvcnRNYXBwaW5ncyguLi5wb3J0TWFwcGluZ3MpO1xuXG4gICAgLy8gd2UgbmVlZCBleHRyYSBwcml2aWxlZ2VzIHRvIGZldGNoIGtleWNsb2FrIGRvY2tlciBpbWFnZXMgZnJvbSBDaGluYSBtaXJyb3Igc2l0ZVxuICAgIHRhc2tEZWZpbml0aW9uLmV4ZWN1dGlvblJvbGU/LmFkZE1hbmFnZWRQb2xpY3koaWFtLk1hbmFnZWRQb2xpY3kuZnJvbUF3c01hbmFnZWRQb2xpY3lOYW1lKCdBbWF6b25FQzJDb250YWluZXJSZWdpc3RyeVJlYWRPbmx5JykpO1xuXG4gICAgdGhpcy5zZXJ2aWNlID0gbmV3IGVjcy5GYXJnYXRlU2VydmljZSh0aGlzLCAnU2VydmljZScsIHtcbiAgICAgIGNsdXN0ZXIsXG4gICAgICB0YXNrRGVmaW5pdGlvbixcbiAgICAgIGNpcmN1aXRCcmVha2VyOiBwcm9wcy5jaXJjdWl0QnJlYWtlciA/IHsgcm9sbGJhY2s6IHRydWUgfSA6IHVuZGVmaW5lZCxcbiAgICAgIGRlc2lyZWRDb3VudDogcHJvcHMubm9kZUNvdW50ID8/IDIsXG4gICAgICBoZWFsdGhDaGVja0dyYWNlUGVyaW9kOiBjZGsuRHVyYXRpb24uc2Vjb25kcygxMjApLFxuICAgIH0pO1xuXG4gICAgdGhpcy5zZXJ2aWNlLmNvbm5lY3Rpb25zLmFsbG93RnJvbSh0aGlzLnNlcnZpY2UuY29ubmVjdGlvbnMsIGVjMi5Qb3J0LnRjcCg3ODAwKSwgJ2tjIGpncm91cHMtdGNwJyk7XG4gICAgdGhpcy5zZXJ2aWNlLmNvbm5lY3Rpb25zLmFsbG93RnJvbSh0aGlzLnNlcnZpY2UuY29ubmVjdGlvbnMsIGVjMi5Qb3J0LnRjcCg1NzgwMCksICdrYyBqZ3JvdXBzLXRjcC1mZCcpO1xuICAgIHMzUGluZ0J1Y2tldCEuZ3JhbnRSZWFkV3JpdGUodGFza0RlZmluaXRpb24udGFza1JvbGUpO1xuXG4gICAgaWYgKHByb3BzLmF1dG9TY2FsZVRhc2spIHtcbiAgICAgIGNvbnN0IG1pbkNhcGFjaXR5ID0gcHJvcHMuYXV0b1NjYWxlVGFzay5taW4gPz8gcHJvcHMubm9kZUNvdW50ID8/IDI7XG4gICAgICBjb25zdCBzY2FsaW5nID0gdGhpcy5zZXJ2aWNlLmF1dG9TY2FsZVRhc2tDb3VudCh7XG4gICAgICAgIG1pbkNhcGFjaXR5LFxuICAgICAgICBtYXhDYXBhY2l0eTogcHJvcHMuYXV0b1NjYWxlVGFzay5tYXggPz8gbWluQ2FwYWNpdHkgKyA1LFxuICAgICAgfSk7XG4gICAgICBzY2FsaW5nLnNjYWxlT25DcHVVdGlsaXphdGlvbignQ3B1U2NhbGluZycsIHtcbiAgICAgICAgdGFyZ2V0VXRpbGl6YXRpb25QZXJjZW50OiBwcm9wcy5hdXRvU2NhbGVUYXNrLnRhcmdldENwdVV0aWxpemF0aW9uID8/IDc1LFxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIC8vIGxpc3RlbmVyIHByb3RvY29sICdUTFMnIGlzIG5vdCBzdXBwb3J0ZWQgd2l0aCBhIHRhcmdldCBncm91cCB3aXRoIHRoZSB0YXJnZXQtdHlwZSAnQUxCJ1xuXG4gICAgdGhpcy5hcHBsaWNhdGlvbkxvYWRCYWxhbmNlciA9IG5ldyBlbGJ2Mi5BcHBsaWNhdGlvbkxvYWRCYWxhbmNlcih0aGlzLCAnQUxCJywge1xuICAgICAgdnBjLFxuICAgICAgdnBjU3VibmV0czogcHJvcHMucHVibGljU3VibmV0cyxcbiAgICAgIGludGVybmV0RmFjaW5nOiB0cnVlLFxuICAgICAgLy8gdnBjU3VibmV0czogcHJvcHMuaW50ZXJuZXRGYWNpbmcgPyBwcm9wcy5wdWJsaWNTdWJuZXRzIDogcHJvcHMucHJpdmF0ZVN1Ym5ldHMsXG4gICAgICAvLyBpbnRlcm5ldEZhY2luZzogcHJvcHMuaW50ZXJuZXRGYWNpbmcsXG4gICAgfSk7XG4gICAgcHJpbnRPdXRwdXQodGhpcywgJ0VuZHBvaW50VVJMJywgYGh0dHBzOi8vJHt0aGlzLmFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyLmxvYWRCYWxhbmNlckRuc05hbWV9YCk7XG5cbiAgICBjb25zdCBsaXN0ZW5lciA9IHRoaXMuYXBwbGljYXRpb25Mb2FkQmFsYW5jZXIuYWRkTGlzdGVuZXIoJ0FMQl9IdHRwc0xpc3RlbmVyJywge1xuICAgICAgcHJvdG9jb2w6IGVsYnYyLkFwcGxpY2F0aW9uUHJvdG9jb2wuSFRUUFMsXG4gICAgICBjZXJ0aWZpY2F0ZXM6IFt7IGNlcnRpZmljYXRlQXJuOiBwcm9wcy5jZXJ0aWZpY2F0ZS5jZXJ0aWZpY2F0ZUFybiB9XSxcbiAgICB9KTtcbiAgICAvLyBcIklmIHRoZSB0YXJnZXQgdHlwZSBpcyBBTEIsIHRoZSB0YXJnZXQgbXVzdCBoYXZlIGF0IGxlYXN0IG9uZSBsaXN0ZW5lciB0aGF0IG1hdGNoZXMgdGhlIHRhcmdldCBncm91cCBwb3J0IG9yIGFueSBzcGVjaWZpZWQgcG9ydCBvdmVycmlkZXNcbiAgICBsaXN0ZW5lci5hZGRUYXJnZXRzKCdFQ1NUYXJnZXQnLCB7XG4gICAgICBwcm90b2NvbDogZWxidjIuQXBwbGljYXRpb25Qcm90b2NvbC5IVFRQLFxuICAgICAgc2xvd1N0YXJ0OiBjZGsuRHVyYXRpb24uc2Vjb25kcyg2MCksXG4gICAgICBzdGlja2luZXNzQ29va2llRHVyYXRpb246IHByb3BzLnN0aWNraW5lc3NDb29raWVEdXJhdGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cygxKSxcbiAgICAgIHRhcmdldHM6IFt0aGlzLnNlcnZpY2VdLFxuICAgICAgaGVhbHRoQ2hlY2s6IHtcbiAgICAgICAgaGVhbHRoeVRocmVzaG9sZENvdW50OiAzLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIGFsbG93IHRhc2sgZXhlY3V0aW9uIHJvbGUgdG8gcmVhZCB0aGUgc2VjcmV0c1xuICAgIHByb3BzLmRhdGFiYXNlLnNlY3JldC5ncmFudFJlYWQodGFza0RlZmluaXRpb24uZXhlY3V0aW9uUm9sZSEpO1xuICAgIHByb3BzLmtleWNsb2FrU2VjcmV0LmdyYW50UmVhZCh0YXNrRGVmaW5pdGlvbi5leGVjdXRpb25Sb2xlISk7XG5cbiAgICAvLyBhbGxvdyBlY3MgdGFzayBjb25uZWN0IHRvIGRhdGFiYXNlXG4gICAgcHJvcHMuZGF0YWJhc2UuY29ubmVjdGlvbnMuYWxsb3dEZWZhdWx0UG9ydEZyb20odGhpcy5zZXJ2aWNlKTtcblxuXG4gICAgLy8gY3JlYXRlIGEgYmFzdGlvbiBob3N0XG4gICAgaWYgKHByb3BzLmJhc3Rpb24gPT09IHRydWUpIHtcbiAgICAgIGNvbnN0IGJhc3QgPSBuZXcgZWMyLkJhc3Rpb25Ib3N0TGludXgodGhpcywgJ0Jhc3QnLCB7XG4gICAgICAgIHZwYyxcbiAgICAgICAgaW5zdGFuY2VUeXBlOiBuZXcgZWMyLkluc3RhbmNlVHlwZSgndDMuc21hbGwnKSxcbiAgICAgIH0pO1xuICAgICAgcHJvcHMuZGF0YWJhc2UuY29ubmVjdGlvbnMuYWxsb3dEZWZhdWx0UG9ydEZyb20oYmFzdCk7XG4gICAgfVxuICB9XG4gIHByaXZhdGUgZ2V0SW1hZ2VVcmlGcm9tTWFwKG1hcDogZG9ja2VySW1hZ2VNYXAsIHZlcnNpb246IHN0cmluZywgaWQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgY29uc3Qgc3RhY2sgPSBjZGsuU3RhY2sub2YodGhpcyk7XG4gICAgaWYgKGNkay5Ub2tlbi5pc1VucmVzb2x2ZWQoc3RhY2sucmVnaW9uKSkge1xuICAgICAgY29uc3QgbWFwcGluZzogeyBbazE6IHN0cmluZ106IHsgW2syOiBzdHJpbmddOiBhbnkgfSB9ID0ge307XG4gICAgICBmb3IgKGxldCBbcGFydGl0aW9uLCB1cmldIG9mIE9iamVjdC5lbnRyaWVzKG1hcCkpIHtcbiAgICAgICAgdXJpICs9IHZlcnNpb247XG4gICAgICAgIG1hcHBpbmdbcGFydGl0aW9uXSA9IHsgdXJpIH07XG4gICAgICB9XG4gICAgICBjb25zdCBpbWFnZU1hcCA9IG5ldyBjZGsuQ2ZuTWFwcGluZyh0aGlzLCBpZCwgeyBtYXBwaW5nIH0pO1xuICAgICAgcmV0dXJuIGltYWdlTWFwLmZpbmRJbk1hcChjZGsuQXdzLlBBUlRJVElPTiwgJ3VyaScpO1xuICAgIH0gZWxzZSB7XG4gICAgICBpZiAoc3RhY2sucmVnaW9uLnN0YXJ0c1dpdGgoJ2NuLScpKSB7XG4gICAgICAgIHJldHVybiBtYXBbJ2F3cy1jbiddICs9IHZlcnNpb247XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gbWFwLmF3cyArPSB2ZXJzaW9uO1xuICAgICAgfVxuICAgIH1cbiAgfVxuICBwcml2YXRlIGdldEtleUNsb2FrRG9ja2VySW1hZ2VVcmkodmVyc2lvbjogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5nZXRJbWFnZVVyaUZyb21NYXAoS0VZQ0xPQUtfRE9DS0VSX0lNQUdFX1VSSV9NQVAsIHZlcnNpb24sICdLZXljbG9ha0ltYWdlTWFwJyk7XG4gIH1cbn1cblxuLyoqXG4gKiBDcmVhdGUgb3IgaW1wb3J0IFZQQ1xuICogQHBhcmFtIHNjb3BlIHRoZSBjZGsgc2NvcGVcbiAqL1xuZnVuY3Rpb24gZ2V0T3JDcmVhdGVWcGMoc2NvcGU6IENvbnN0cnVjdCk6IGVjMi5JVnBjIHtcbiAgLy8gdXNlIGFuIGV4aXN0aW5nIHZwYyBvciBjcmVhdGUgYSBuZXcgb25lXG4gIHJldHVybiBzY29wZS5ub2RlLnRyeUdldENvbnRleHQoJ3VzZV9kZWZhdWx0X3ZwYycpID09PSAnMScgP1xuICAgIGVjMi5WcGMuZnJvbUxvb2t1cChzY29wZSwgJ1ZwYycsIHsgaXNEZWZhdWx0OiB0cnVlIH0pIDpcbiAgICBzY29wZS5ub2RlLnRyeUdldENvbnRleHQoJ3VzZV92cGNfaWQnKSA/XG4gICAgICBlYzIuVnBjLmZyb21Mb29rdXAoc2NvcGUsICdWcGMnLCB7IHZwY0lkOiBzY29wZS5ub2RlLnRyeUdldENvbnRleHQoJ3VzZV92cGNfaWQnKSB9KSA6XG4gICAgICBuZXcgZWMyLlZwYyhzY29wZSwgJ1ZwYycsIHsgbWF4QXpzOiAzLCBuYXRHYXRld2F5czogMSB9KTtcbn1cblxuZnVuY3Rpb24gcHJpbnRPdXRwdXQoc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywga2V5OiBzdHJpbmcgfCBudW1iZXIpIHtcbiAgbmV3IGNkay5DZm5PdXRwdXQoc2NvcGUsIGlkLCB7IHZhbHVlOiBTdHJpbmcoa2V5KSB9KTtcbn1cbiJdfQ==