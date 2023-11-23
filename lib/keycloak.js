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
        const { cpu = 2048, memoryLimitMiB = 4096 } = props;
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
        const s3PingBucket = new aws_cdk_lib_1.aws_s3.Bucket(this, 'keycloak_s3_ping');
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoia2V5Y2xvYWsuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMva2V5Y2xvYWsudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSxtQ0FBbUM7QUFDbkMsNkNBU3FCO0FBQ3JCLDJDQUF1QztBQUV2Qyw4Q0FBOEM7QUFDOUMsc0hBQXNIO0FBQ3RILE1BQU0sbUNBQW1DLEdBQUc7SUFDMUMsV0FBVztJQUNYLFdBQVc7SUFDWCxXQUFXO0lBQ1gsV0FBVztJQUNYLFlBQVk7SUFDWixnQkFBZ0I7SUFDaEIsZ0JBQWdCO0lBQ2hCLGdCQUFnQjtJQUNoQixnQkFBZ0I7SUFDaEIsY0FBYztJQUNkLGNBQWM7SUFDZCxXQUFXO0lBQ1gsV0FBVztJQUNYLFdBQVc7SUFDWCxnQkFBZ0I7Q0FDakIsQ0FBQztBQUVGOztHQUVHO0FBQ0gsTUFBYSxlQUFlO0lBNkQxQjs7O09BR0c7SUFDSCxZQUFvQyxPQUFlO1FBQWYsWUFBTyxHQUFQLE9BQU8sQ0FBUTtJQUFJLENBQUM7SUFUeEQ7OztPQUdHO0lBQ0ksTUFBTSxDQUFDLEVBQUUsQ0FBQyxPQUFlLElBQUksT0FBTyxJQUFJLGVBQWUsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUM7O0FBNUQ1RSwwQ0FrRUM7OztBQWpFQzs7R0FFRztBQUNvQix1QkFBTyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUM7QUFFOUQ7O0dBRUc7QUFDb0IsdUJBQU8sR0FBRyxlQUFlLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBRTlEOztHQUVHO0FBQ29CLHVCQUFPLEdBQUcsZUFBZSxDQUFDLEVBQUUsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUU5RDs7R0FFRztBQUNvQix1QkFBTyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUM7QUFFOUQ7O0dBRUc7QUFDb0IsdUJBQU8sR0FBRyxlQUFlLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBRTlE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b0I7SUFDckUsSUFBSSxHQUFHLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxFQUFFLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUN2RCxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgY2RrIGZyb20gJ2F3cy1jZGstbGliJztcbmltcG9ydCB7XG4gIGF3c19jZXJ0aWZpY2F0ZW1hbmFnZXIgYXMgY2VydG1ncixcbiAgYXdzX2VjMiBhcyBlYzIsIGF3c19lY3MgYXMgZWNzLCBhd3NfZWxhc3RpY2xvYWRiYWxhbmNpbmd2MiBhcyBlbGJ2MixcbiAgLy8gYXdzX2VsYXN0aWNsb2FkYmFsYW5jaW5ndjJfdGFyZ2V0cyBhcyBlbGJUYXJnZXRzLFxuICBhd3NfaWFtIGFzIGlhbSxcbiAgYXdzX2xvZ3MgYXMgbG9ncyxcbiAgYXdzX3JkcyBhcyByZHMsXG4gIGF3c19zMyBhcyBzMyxcbiAgYXdzX3NlY3JldHNtYW5hZ2VyIGFzIHNlY3JldHNtYW5hZ2VyLFxufSBmcm9tICdhd3MtY2RrLWxpYic7XG5pbXBvcnQgeyBDb25zdHJ1Y3QgfSBmcm9tICdjb25zdHJ1Y3RzJztcblxuLy8gcmVnaW9uYWwgYXZhaWxpYmlsaXR5IGZvciBhdXJvcmEgc2VydmVybGVzc1xuLy8gc2VlIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9BbWF6b25SRFMvbGF0ZXN0L0F1cm9yYVVzZXJHdWlkZS9Db25jZXB0cy5BdXJvcmFGZWF0dXJlc1JlZ2lvbnNEQkVuZ2luZXMuZ3JpZHMuaHRtbFxuY29uc3QgQVVST1JBX1NFUlZFUkxFU1NfU1VQUE9SVEVEX1JFR0lPTlMgPSBbXG4gICd1cy1lYXN0LTEnLFxuICAndXMtZWFzdC0yJyxcbiAgJ3VzLXdlc3QtMScsXG4gICd1cy13ZXN0LTInLFxuICAnYXAtc291dGgtMScsXG4gICdhcC1ub3J0aGVhc3QtMScsXG4gICdhcC1ub3J0aGVhc3QtMicsXG4gICdhcC1zb3V0aGVhc3QtMScsXG4gICdhcC1zb3V0aGVhc3QtMicsXG4gICdjYS1jZW50cmFsLTEnLFxuICAnZXUtY2VudHJhbC0xJyxcbiAgJ2V1LXdlc3QtMScsXG4gICdldS13ZXN0LTInLFxuICAnZXUtd2VzdC0zJyxcbiAgJ2NuLW5vcnRod2VzdC0xJyxcbl07XG5cbi8qKlxuICogS2V5Y2xvYWsgIHZlcnNpb25cbiAqL1xuZXhwb3J0IGNsYXNzIEtleWNsb2FrVmVyc2lvbiB7XG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDEyLjAuNFxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTJfMF80ID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxMi4wLjQnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxNS4wLjBcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE1XzBfMCA9IEtleWNsb2FrVmVyc2lvbi5vZignMTUuMC4wJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTUuMC4xXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxNV8wXzEgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE1LjAuMScpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE1LjAuMlxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTVfMF8yID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxNS4wLjInKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxNi4xLjFcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE2XzFfMSA9IEtleWNsb2FrVmVyc2lvbi5vZignMTYuMS4xJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTcuMC4xXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxN18wXzEgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE3LjAuMScpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE4LjAuMlxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMThfMF8zID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxOC4wLjInKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxOS4wLjNcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE5XzBfMyA9IEtleWNsb2FrVmVyc2lvbi5vZignMTkuMC4zJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMjAuMC41XG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYyMF8wXzMgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzIwLjAuNScpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDIxLjAuMFxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMjFfMF8wID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcyMS4wLjAnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAyMS4wLjFcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjIxXzBfMSA9IEtleWNsb2FrVmVyc2lvbi5vZignMjEuMC4xJyk7XG5cbiAgLyoqXG4gICAqIEN1c3RvbSBjbHVzdGVyIHZlcnNpb25cbiAgICogQHBhcmFtIHZlcnNpb24gY3VzdG9tIHZlcnNpb24gbnVtYmVyXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIG9mKHZlcnNpb246IHN0cmluZykgeyByZXR1cm4gbmV3IEtleWNsb2FrVmVyc2lvbih2ZXJzaW9uKTsgfVxuICAvKipcbiAgICpcbiAgICogQHBhcmFtIHZlcnNpb24gY2x1c3RlciB2ZXJzaW9uIG51bWJlclxuICAgKi9cbiAgcHJpdmF0ZSBjb25zdHJ1Y3RvcihwdWJsaWMgcmVhZG9ubHkgdmVyc2lvbjogc3RyaW5nKSB7IH1cbn1cblxuaW50ZXJmYWNlIGRvY2tlckltYWdlTWFwIHtcbiAgJ2F3cyc6IHN0cmluZztcbiAgJ2F3cy1jbic6IHN0cmluZztcbn1cblxuY29uc3QgS0VZQ0xPQUtfRE9DS0VSX0lNQUdFX1VSSV9NQVA6IGRvY2tlckltYWdlTWFwID0ge1xuICAnYXdzJzogJ3F1YXkuaW8va2V5Y2xvYWsva2V5Y2xvYWs6JyxcbiAgJ2F3cy1jbic6ICcwNDg5MTIwNjA5MTAuZGtyLmVjci5jbi1ub3J0aHdlc3QtMS5hbWF6b25hd3MuY29tLmNuL2RvY2tlcmh1Yi9qYm9zcy9rZXljbG9hazonLFxufTtcblxuLyoqXG4gKiBUaGUgRUNTIHRhc2sgYXV0b3NjYWxpbmcgZGVmaW5pdGlvblxuICovXG5leHBvcnQgaW50ZXJmYWNlIEF1dG9TY2FsZVRhc2sge1xuICAvKipcbiAgICogVGhlIG1pbmltYWwgY291bnQgb2YgdGhlIHRhc2sgbnVtYmVyXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gbm9kZUNvdW50XG4gICAqL1xuICByZWFkb25seSBtaW4/OiBudW1iZXI7XG4gIC8qKlxuICAgKiBUaGUgbWF4aW1hbCBjb3VudCBvZiB0aGUgdGFzayBudW1iZXJcbiAgICpcbiAgICogQGRlZmF1bHQgLSBtaW4gKyA1XG4gICAqL1xuICByZWFkb25seSBtYXg/OiBudW1iZXI7XG4gIC8qKlxuICAgKiBUaGUgdGFyZ2V0IGNwdSB1dGlsaXphdGlvbiBmb3IgdGhlIHNlcnZpY2UgYXV0b3NjYWxpbmdcbiAgICpcbiAgICogQGRlZmF1bHQgNzVcbiAgICovXG4gIHJlYWRvbmx5IHRhcmdldENwdVV0aWxpemF0aW9uPzogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEtleUNsb2FrUHJvcHMge1xuICAvKipcbiAgICogVGhlIEtleWNsb2FrIHZlcnNpb24gZm9yIHRoZSBjbHVzdGVyLlxuICAgKi9cbiAgcmVhZG9ubHkga2V5Y2xvYWtWZXJzaW9uOiBLZXljbG9ha1ZlcnNpb247XG4gIC8qKlxuICAgKiBUaGUgZW52aXJvbm1lbnQgdmFyaWFibGVzIHRvIHBhc3MgdG8gdGhlIGtleWNsb2FrIGNvbnRhaW5lclxuICAgKi9cbiAgcmVhZG9ubHkgZW52PzogeyBba2V5OiBzdHJpbmddOiBzdHJpbmcgfTtcbiAgLyoqXG4gICAqIFZQQyBmb3IgdGhlIHdvcmtsb2FkXG4gICAqL1xuICByZWFkb25seSB2cGM/OiBlYzIuSVZwYztcbiAgLyoqXG4gICAqIEFDTSBjZXJ0aWZpY2F0ZSBBUk4gdG8gaW1wb3J0XG4gICAqL1xuICByZWFkb25seSBjZXJ0aWZpY2F0ZUFybjogc3RyaW5nO1xuICAvKipcbiAgICogQ3JlYXRlIGEgYmFzdGlvbiBob3N0IGZvciBkZWJ1Z2dpbmcgb3IgdHJvdWJsZS1zaG9vdGluZ1xuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYmFzdGlvbj86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBOdW1iZXIgb2Yga2V5Y2xvYWsgbm9kZSBpbiB0aGUgY2x1c3RlclxuICAgKlxuICAgKiBAZGVmYXVsdCAyXG4gICAqL1xuICByZWFkb25seSBub2RlQ291bnQ/OiBudW1iZXI7XG4gIC8qKlxuICAgKiBWUEMgcHVibGljIHN1Ym5ldHMgZm9yIEFMQlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFZQQyBwdWJsaWMgc3VibmV0c1xuICAgKi9cbiAgcmVhZG9ubHkgcHVibGljU3VibmV0cz86IGVjMi5TdWJuZXRTZWxlY3Rpb247XG4gIC8qKlxuICAgKiBWUEMgcHJpdmF0ZSBzdWJuZXRzIGZvciBrZXljbG9hayBzZXJ2aWNlXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gVlBDIHByaXZhdGUgc3VibmV0c1xuICAgKi9cbiAgcmVhZG9ubHkgcHJpdmF0ZVN1Ym5ldHM/OiBlYzIuU3VibmV0U2VsZWN0aW9uO1xuICAvKipcbiAgICogVlBDIHN1Ym5ldHMgZm9yIGRhdGFiYXNlXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gVlBDIGlzb2xhdGVkIHN1Ym5ldHNcbiAgICovXG4gIHJlYWRvbmx5IGRhdGFiYXNlU3VibmV0cz86IGVjMi5TdWJuZXRTZWxlY3Rpb247XG4gIC8qKlxuICAgKiBEYXRhYmFzZSBpbnN0YW5jZSB0eXBlXG4gICAqXG4gICAqIEBkZWZhdWx0IHI1LmxhcmdlXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZUluc3RhbmNlVHlwZT86IGVjMi5JbnN0YW5jZVR5cGU7XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2UgaW5zdGFuY2UgZW5naW5lXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTXlTUUwgOC4wLjIxXG4gICAqL1xuICByZWFkb25seSBpbnN0YW5jZUVuZ2luZT86IHJkcy5JSW5zdGFuY2VFbmdpbmU7XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2UgY2x1c3RlciBlbmdpbmVcbiAgICpcbiAgICogQGRlZmF1bHQgcmRzLkF1cm9yYU15c3FsRW5naW5lVmVyc2lvbi5WRVJfMl8wOV8xXG4gICAqL1xuICByZWFkb25seSBjbHVzdGVyRW5naW5lPzogcmRzLklDbHVzdGVyRW5naW5lO1xuICAvKipcbiAgICogV2hldGhlciB0byB1c2UgYXVyb3JhIHNlcnZlcmxlc3MuIFdoZW4gZW5hYmxlZCwgdGhlIGBkYXRhYmFzZUluc3RhbmNlVHlwZWAgYW5kXG4gICAqIGBlbmdpbmVgIHdpbGwgYmUgaWdub3JlZC4gVGhlIGByZHMuRGF0YWJhc2VDbHVzdGVyRW5naW5lLkFVUk9SQV9NWVNRTGAgd2lsbCBiZSB1c2VkIGFzXG4gICAqIHRoZSBkZWZhdWx0IGNsdXN0ZXIgZW5naW5lIGluc3RlYWQuXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBhdXJvcmFTZXJ2ZXJsZXNzPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gdXNlIGF1cm9yYSBzZXJ2ZXJsZXNzIHYyLiBXaGVuIGVuYWJsZWQsIHRoZSBgZGF0YWJhc2VJbnN0YW5jZVR5cGVgIHdpbGwgYmUgaWdub3JlZC5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGF1cm9yYVNlcnZlcmxlc3NWMj86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHVzZSBzaW5nbGUgUkRTIGluc3RhbmNlIHJhdGhlciB0aGFuIFJEUyBjbHVzdGVyLiBOb3QgcmVjb21tZW5kZWQgZm9yIHByb2R1Y3Rpb24uXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBzaW5nbGVEYkluc3RhbmNlPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIGRhdGFiYXNlIGJhY2t1cCByZXRlbnNpb25cbiAgICpcbiAgICogQGRlZmF1bHQgLSA3IGRheXNcbiAgICovXG4gIHJlYWRvbmx5IGJhY2t1cFJldGVudGlvbj86IGNkay5EdXJhdGlvbjtcbiAgLyoqXG4gICAqIFRoZSBzdGlja3kgc2Vzc2lvbiBkdXJhdGlvbiBmb3IgdGhlIGtleWNsb2FrIHdvcmtsb2FkIHdpdGggQUxCLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIG9uZSBkYXlcbiAgICovXG4gIHJlYWRvbmx5IHN0aWNraW5lc3NDb29raWVEdXJhdGlvbj86IGNkay5EdXJhdGlvbjtcbiAgLyoqXG4gICAqIEF1dG9zY2FsaW5nIGZvciB0aGUgRUNTIFNlcnZpY2VcbiAgICpcbiAgICogQGRlZmF1bHQgLSBubyBlY3Mgc2VydmljZSBhdXRvc2NhbGluZ1xuICAgKi9cbiAgcmVhZG9ubHkgYXV0b1NjYWxlVGFzaz86IEF1dG9TY2FsZVRhc2s7XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gcHV0IHRoZSBsb2FkIGJhbGFuY2VyIGluIHRoZSBwdWJsaWMgb3IgcHJpdmF0ZSBzdWJuZXRzXG4gICAqXG4gICAqIEBkZWZhdWx0IHRydWVcbiAgICovXG4gIHJlYWRvbmx5IGludGVybmV0RmFjaW5nPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogVGhlIGhvc3RuYW1lIHRvIHVzZSBmb3IgdGhlIGtleWNsb2FrIHNlcnZlclxuICAgKi9cbiAgcmVhZG9ubHkgaG9zdG5hbWU/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSBtaW5pbXVtIG51bWJlciBvZiBBdXJvcmEgU2VydmVybGVzcyBWMiBjYXBhY2l0eSB1bml0cy5cbiAgICpcbiAgICogQGRlZmF1bHQgMC41XG4gICovXG4gIHJlYWRvbmx5IGRhdGFiYXNlTWluQ2FwYWNpdHk/OiBudW1iZXI7XG5cbiAgLyoqXG4gICogVGhlIG1heGltdW0gbnVtYmVyIG9mIEF1cm9yYSBTZXJ2ZXJsZXNzIFYyIGNhcGFjaXR5IHVuaXRzLlxuICAqXG4gICAqIEBkZWZhdWx0IDEwXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZU1heENhcGFjaXR5PzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBDb250cm9scyB3aGF0IGhhcHBlbnMgdG8gdGhlIGRhdGFiYXNlIGlmIGl0IHN0b3BzIGJlaW5nIG1hbmFnZWQgYnkgQ2xvdWRGb3JtYXRpb25cbiAgICpcbiAgICogQGRlZmF1bHQgUmVtb3ZhbFBvbGljeS5SRVRBSU5cbiAgICovXG4gIHJlYWRvbmx5IGRhdGFiYXNlUmVtb3ZhbFBvbGljeT86IGNkay5SZW1vdmFsUG9saWN5O1xuXG5cbiAgLyoqXG4gICAqIE92ZXJyaWRlcyB0aGUgZGVmYXVsdCBpbWFnZVxuICAgKlxuICAgKiBAZGVmYXVsdCBxdWF5LmlvL2tleWNsb2FrL2tleWNsb2FrOiR7S0VZQ0xPQUtfVkVSU0lPTn1cbiAgICovXG4gIHJlYWRvbmx5IGNvbnRhaW5lckltYWdlPzogZWNzLkNvbnRhaW5lckltYWdlO1xuXG4gIC8qKlxuICAgKiBUaGUgbnVtYmVyIG9mIGNwdSB1bml0cyB1c2VkIGJ5IHRoZSBLZXljbG9hayB0YXNrLlxuICAgKiBZb3UgbXVzdCB1c2Ugb25lIG9mIHRoZSBmb2xsb3dpbmcgdmFsdWVzLCB3aGljaCBkZXRlcm1pbmVzIHlvdXIgcmFuZ2Ugb2YgdmFsaWQgdmFsdWVzIGZvciB0aGUgbWVtb3J5IHBhcmFtZXRlcjpcbiAgICogMjU2ICguMjUgdkNQVSkgLSBBdmFpbGFibGUgbWVtb3J5IHZhbHVlczogNTEyICgwLjUgR0IpLCAxMDI0ICgxIEdCKSwgMjA0OCAoMiBHQilcbiAgICogNTEyICguNSB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiAxMDI0ICgxIEdCKSwgMjA0OCAoMiBHQiksIDMwNzIgKDMgR0IpLCA0MDk2ICg0IEdCKVxuICAgKiAxMDI0ICgxIHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IDIwNDggKDIgR0IpLCAzMDcyICgzIEdCKSwgNDA5NiAoNCBHQiksIDUxMjAgKDUgR0IpLCA2MTQ0ICg2IEdCKSwgNzE2OCAoNyBHQiksIDgxOTIgKDggR0IpXG4gICAqIDIwNDggKDIgdkNQVSkgLSBBdmFpbGFibGUgbWVtb3J5IHZhbHVlczogQmV0d2VlbiA0MDk2ICg0IEdCKSBhbmQgMTYzODQgKDE2IEdCKSBpbiBpbmNyZW1lbnRzIG9mIDEwMjQgKDEgR0IpXG4gICAqIDQwOTYgKDQgdkNQVSkgLSBBdmFpbGFibGUgbWVtb3J5IHZhbHVlczogQmV0d2VlbiA4MTkyICg4IEdCKSBhbmQgMzA3MjAgKDMwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDEwMjQgKDEgR0IpXG4gICAqIDgxOTIgKDggdkNQVSkgLSBBdmFpbGFibGUgbWVtb3J5IHZhbHVlczogQmV0d2VlbiAxNjM4NCAoMTYgR0IpIGFuZCA2MTQ0MCAoNjAgR0IpIGluIGluY3JlbWVudHMgb2YgNDA5NiAoNCBHQilcbiAgICogMTYzODQgKDE2IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gMzI3NjggKDMyIEdCKSBhbmQgMTIyODgwICgxMjAgR0IpIGluIGluY3JlbWVudHMgb2YgODE5MiAoOCBHQilcbiAgICpcbiAgICogQGRlZmF1bHQgMjA0OFxuICAgKi9cbiAgcmVhZG9ubHkgY3B1PzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBUaGUgYW1vdW50IChpbiBNaUIpIG9mIG1lbW9yeSB1c2VkIGJ5IHRoZSB0YXNrLlxuICAgKiBZb3UgbXVzdCB1c2Ugb25lIG9mIHRoZSBmb2xsb3dpbmcgdmFsdWVzLCB3aGljaCBkZXRlcm1pbmVzIHlvdXIgcmFuZ2Ugb2YgdmFsaWQgdmFsdWVzIGZvciB0aGUgY3B1IHBhcmFtZXRlcjpcbiAgICogNTEyICgwLjUgR0IpLCAxMDI0ICgxIEdCKSwgMjA0OCAoMiBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMjU2ICguMjUgdkNQVSlcbiAgICogMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpLCAzMDcyICgzIEdCKSwgNDA5NiAoNCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogNTEyICguNSB2Q1BVKVxuICAgKiAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpLCA1MTIwICg1IEdCKSwgNjE0NCAoNiBHQiksIDcxNjggKDcgR0IpLCA4MTkyICg4IEdCKSAtIEF2YWlsYWJsZSBjcHUgdmFsdWVzOiAxMDI0ICgxIHZDUFUpXG4gICAqIEJldHdlZW4gNDA5NiAoNCBHQikgYW5kIDE2Mzg0ICgxNiBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKSAtIEF2YWlsYWJsZSBjcHUgdmFsdWVzOiAyMDQ4ICgyIHZDUFUpXG4gICAqIEJldHdlZW4gODE5MiAoOCBHQikgYW5kIDMwNzIwICgzMCBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKSAtIEF2YWlsYWJsZSBjcHUgdmFsdWVzOiA0MDk2ICg0IHZDUFUpXG4gICAqIEJldHdlZW4gMTYzODQgKDE2IEdCKSBhbmQgNjE0NDAgKDYwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDQwOTYgKDQgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDgxOTIgKDggdkNQVSlcbiAgICogQmV0d2VlbiAzMjc2OCAoMzIgR0IpIGFuZCAxMjI4ODAgKDEyMCBHQikgaW4gaW5jcmVtZW50cyBvZiA4MTkyICg4IEdCKSAtIEF2YWlsYWJsZSBjcHUgdmFsdWVzOiAxNjM4NCAoMTYgdkNQVSlcbiAgICpcbiAgICogQGRlZmF1bHQgNDA5NlxuICAgKi9cbiAgcmVhZG9ubHkgbWVtb3J5TGltaXRNaUI/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBjbGFzcyBLZXlDbG9hayBleHRlbmRzIENvbnN0cnVjdCB7XG4gIHJlYWRvbmx5IHZwYzogZWMyLklWcGM7XG4gIHJlYWRvbmx5IGRiPzogRGF0YWJhc2U7XG4gIHJlYWRvbmx5IGFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyOiBlbGJ2Mi5BcHBsaWNhdGlvbkxvYWRCYWxhbmNlcjtcbiAgLy8gcmVhZG9ubHkgbmV0d29ya0xvYWRCYWxhbmNlcjogZWxidjIuTmV0d29ya0xvYWRCYWxhbmNlcjtcbiAgcmVhZG9ubHkga2V5Y2xvYWtTZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBLZXlDbG9ha1Byb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkKTtcblxuICAgIGNvbnN0IHJlZ2lvbiA9IGNkay5TdGFjay5vZih0aGlzKS5yZWdpb247XG4gICAgY29uc3QgcmVnaW9uSXNSZXNvbHZlZCA9ICFjZGsuVG9rZW4uaXNVbnJlc29sdmVkKHJlZ2lvbik7XG4gICAgY29uc3QgeyBjcHUgPSAyMDQ4LCBtZW1vcnlMaW1pdE1pQiA9NDA5NiB9ID0gcHJvcHM7XG5cbiAgICBpZiAocHJvcHMuYXVyb3JhU2VydmVybGVzcyAmJiByZWdpb25Jc1Jlc29sdmVkICYmICFBVVJPUkFfU0VSVkVSTEVTU19TVVBQT1JURURfUkVHSU9OUy5pbmNsdWRlcyhyZWdpb24pKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYEF1cm9yYSBzZXJ2ZXJsZXNzIGlzIG5vdCBzdXBwb3J0ZWQgaW4gJHtyZWdpb259YCk7XG4gICAgfVxuXG4gICAgdGhpcy5rZXljbG9ha1NlY3JldCA9IHRoaXMuX2dlbmVyYXRlS2V5Y2xvYWtTZWNyZXQoKTtcbiAgICB0aGlzLnZwYyA9IHByb3BzLnZwYyA/PyBnZXRPckNyZWF0ZVZwYyh0aGlzKTtcblxuICAgIHRoaXMuZGIgPSB0aGlzLmFkZERhdGFiYXNlKHtcbiAgICAgIHZwYzogdGhpcy52cGMsXG4gICAgICBkYXRhYmFzZVN1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgIGluc3RhbmNlVHlwZTogcHJvcHMuZGF0YWJhc2VJbnN0YW5jZVR5cGUsXG4gICAgICBpbnN0YW5jZUVuZ2luZTogcHJvcHMuaW5zdGFuY2VFbmdpbmUsXG4gICAgICBjbHVzdGVyRW5naW5lOiBwcm9wcy5jbHVzdGVyRW5naW5lLFxuICAgICAgYXVyb3JhU2VydmVybGVzczogZmFsc2UsXG4gICAgICBhdXJvcmFTZXJ2ZXJsZXNzVjI6IGZhbHNlLFxuICAgICAgc2luZ2xlRGJJbnN0YW5jZTogcHJvcHMuc2luZ2xlRGJJbnN0YW5jZSxcbiAgICAgIGJhY2t1cFJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uLFxuICAgICAgbWF4Q2FwYWNpdHk6IHByb3BzLmRhdGFiYXNlTWF4Q2FwYWNpdHksXG4gICAgICBtaW5DYXBhY2l0eTogcHJvcHMuZGF0YWJhc2VNaW5DYXBhY2l0eSxcbiAgICAgIHJlbW92YWxQb2xpY3k6IHByb3BzLmRhdGFiYXNlUmVtb3ZhbFBvbGljeSxcbiAgICB9KTtcbiAgICBjb25zdCBrZXljbG9ha0NvbnRhaW5lclNlcnZpY2UgPSB0aGlzLmFkZEtleUNsb2FrQ29udGFpbmVyU2VydmljZSh7XG4gICAgICBkYXRhYmFzZTogdGhpcy5kYixcbiAgICAgIHZwYzogdGhpcy52cGMsXG4gICAgICBrZXljbG9ha1ZlcnNpb246IHByb3BzLmtleWNsb2FrVmVyc2lvbixcbiAgICAgIHB1YmxpY1N1Ym5ldHM6IHByb3BzLnB1YmxpY1N1Ym5ldHMsXG4gICAgICBwcml2YXRlU3VibmV0czogcHJvcHMucHJpdmF0ZVN1Ym5ldHMsXG4gICAgICBrZXljbG9ha1NlY3JldDogdGhpcy5rZXljbG9ha1NlY3JldCxcbiAgICAgIGNlcnRpZmljYXRlOiBjZXJ0bWdyLkNlcnRpZmljYXRlLmZyb21DZXJ0aWZpY2F0ZUFybih0aGlzLCAnQUNNQ2VydCcsIHByb3BzLmNlcnRpZmljYXRlQXJuKSxcbiAgICAgIGJhc3Rpb246IHByb3BzLmJhc3Rpb24sXG4gICAgICBub2RlQ291bnQ6IHByb3BzLm5vZGVDb3VudCxcbiAgICAgIHN0aWNraW5lc3NDb29raWVEdXJhdGlvbjogcHJvcHMuc3RpY2tpbmVzc0Nvb2tpZUR1cmF0aW9uLFxuICAgICAgYXV0b1NjYWxlVGFzazogcHJvcHMuYXV0b1NjYWxlVGFzayxcbiAgICAgIGVudjogcHJvcHMuZW52LFxuICAgICAgaW50ZXJuZXRGYWNpbmc6IHByb3BzLmludGVybmV0RmFjaW5nID8/IHRydWUsXG4gICAgICBob3N0bmFtZTogcHJvcHMuaG9zdG5hbWUsXG4gICAgICBjb250YWluZXJJbWFnZTogcHJvcHMuY29udGFpbmVySW1hZ2UsXG4gICAgICBjcHUsXG4gICAgICBtZW1vcnlMaW1pdE1pQixcbiAgICB9KTtcblxuICAgIHRoaXMuYXBwbGljYXRpb25Mb2FkQmFsYW5jZXIgPSBrZXljbG9ha0NvbnRhaW5lclNlcnZpY2UuYXBwbGljYXRpb25Mb2FkQmFsYW5jZXI7XG4gICAgLy8gdGhpcy5uZXR3b3JrTG9hZEJhbGFuY2VyID0ga2V5Y2xvYWtDb250YWluZXJTZXJ2aWNlLm5ldHdvcmtMb2FkQmFsYW5jZXI7XG4gICAgaWYgKCFjZGsuU3RhY2sub2YodGhpcykudGVtcGxhdGVPcHRpb25zLmRlc2NyaXB0aW9uKSB7XG4gICAgICBjZGsuU3RhY2sub2YodGhpcykudGVtcGxhdGVPcHRpb25zLmRlc2NyaXB0aW9uID0gJyhTTzgwMjEpIC0gRGVwbG95IGtleWNsb2FrIG9uIEFXUyB3aXRoIGNkay1rZXljbG9hayBjb25zdHJ1Y3QgbGlicmFyeSc7XG4gICAgfVxuICB9XG4gIHB1YmxpYyBhZGREYXRhYmFzZShwcm9wczogRGF0YWJhc2VQcm9wcyk6IERhdGFiYXNlIHtcbiAgICByZXR1cm4gbmV3IERhdGFiYXNlKHRoaXMsICdEYXRhYmFzZScsIHByb3BzKTtcbiAgfVxuICBwdWJsaWMgYWRkS2V5Q2xvYWtDb250YWluZXJTZXJ2aWNlKHByb3BzOiBDb250YWluZXJTZXJ2aWNlUHJvcHMpIHtcbiAgICByZXR1cm4gbmV3IENvbnRhaW5lclNlcnZpY2UodGhpcywgJ0tleUNsb2FrQ29udGFpbmVyU2VyaXZjZScsIHByb3BzKTtcbiAgfVxuICBwcml2YXRlIF9nZW5lcmF0ZUtleWNsb2FrU2VjcmV0KCk6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQge1xuICAgIHJldHVybiBuZXcgc2VjcmV0c21hbmFnZXIuU2VjcmV0KHRoaXMsICdLQ1NlY3JldCcsIHtcbiAgICAgIGdlbmVyYXRlU2VjcmV0U3RyaW5nOiB7XG4gICAgICAgIGdlbmVyYXRlU3RyaW5nS2V5OiAncGFzc3dvcmQnLFxuICAgICAgICBleGNsdWRlUHVuY3R1YXRpb246IHRydWUsXG4gICAgICAgIHBhc3N3b3JkTGVuZ3RoOiAxMixcbiAgICAgICAgc2VjcmV0U3RyaW5nVGVtcGxhdGU6IEpTT04uc3RyaW5naWZ5KHsgdXNlcm5hbWU6ICdrZXljbG9haycgfSksXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGF0YWJhc2VQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgVlBDIGZvciB0aGUgZGF0YWJhc2VcbiAgICovXG4gIHJlYWRvbmx5IHZwYzogZWMyLklWcGM7XG4gIC8qKlxuICAgKiBWUEMgc3VibmV0cyBmb3IgZGF0YWJhc2VcbiAgICovXG4gIHJlYWRvbmx5IGRhdGFiYXNlU3VibmV0cz86IGVjMi5TdWJuZXRTZWxlY3Rpb247XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2UgaW5zdGFuY2UgdHlwZVxuICAgKlxuICAgKiBAZGVmYXVsdCByNS5sYXJnZVxuICAgKi9cbiAgcmVhZG9ubHkgaW5zdGFuY2VUeXBlPzogZWMyLkluc3RhbmNlVHlwZTtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBpbnN0YW5jZSBlbmdpbmVcbiAgICpcbiAgICogQGRlZmF1bHQgLSBNeVNRTCA4LjAuMjFcbiAgICovXG4gIHJlYWRvbmx5IGluc3RhbmNlRW5naW5lPzogcmRzLklJbnN0YW5jZUVuZ2luZTtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBjbHVzdGVyIGVuZ2luZVxuICAgKlxuICAgKiBAZGVmYXVsdCByZHMuQXVyb3JhTXlzcWxFbmdpbmVWZXJzaW9uLlZFUl8yXzA5XzFcbiAgICovXG4gIHJlYWRvbmx5IGNsdXN0ZXJFbmdpbmU/OiByZHMuSUNsdXN0ZXJFbmdpbmU7XG4gIC8qKlxuICAgKiBlbmFibGUgYXVyb3JhIHNlcnZlcmxlc3NcbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGF1cm9yYVNlcnZlcmxlc3M/OiBib29sZWFuO1xuICAvKipcbiAgICogZW5hYmxlIGF1cm9yYSBzZXJ2ZXJsZXNzIHYyXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBhdXJvcmFTZXJ2ZXJsZXNzVjI/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHVzZSBzaW5nbGUgUkRTIGluc3RhbmNlIHJhdGhlciB0aGFuIFJEUyBjbHVzdGVyLiBOb3QgcmVjb21tZW5kZWQgZm9yIHByb2R1Y3Rpb24uXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBzaW5nbGVEYkluc3RhbmNlPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIGRhdGFiYXNlIGJhY2t1cCByZXRlbnNpb25cbiAgICpcbiAgICogQGRlZmF1bHQgLSA3IGRheXNcbiAgICovXG4gIHJlYWRvbmx5IGJhY2t1cFJldGVudGlvbj86IGNkay5EdXJhdGlvbjtcbiAgLyoqXG4gICAqIFRoZSBtaW5pbXVtIG51bWJlciBvZiBBdXJvcmEgU2VydmVybGVzcyBWMiBjYXBhY2l0eSB1bml0cy5cbiAgICpcbiAgICogQGRlZmF1bHQgMC41XG4gICovXG4gIHJlYWRvbmx5IG1pbkNhcGFjaXR5PzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIG1heGltdW0gbnVtYmVyIG9mIEF1cm9yYSBTZXJ2ZXJsZXNzIFYyIGNhcGFjaXR5IHVuaXRzLlxuICAgKlxuICAgKiBAZGVmYXVsdCAxMFxuICAgKi9cbiAgcmVhZG9ubHkgbWF4Q2FwYWNpdHk/OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIENvbnRyb2xzIHdoYXQgaGFwcGVucyB0byB0aGUgZGF0YWJhc2UgaWYgaXQgc3RvcHMgYmVpbmcgbWFuYWdlZCBieSBDbG91ZEZvcm1hdGlvblxuICAgKlxuICAgKiBAZGVmYXVsdCBSZW1vdmFsUG9saWN5LlJFVEFJTlxuICAgKi9cbiAgcmVhZG9ubHkgcmVtb3ZhbFBvbGljeT86IGNkay5SZW1vdmFsUG9saWN5O1xufVxuXG4vKipcbiAqIERhdGFiYXNlIGNvbmZpZ3VyYXRpb25cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBEYXRhYmFzZUNvbmZpZyB7XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2Ugc2VjcmV0LlxuICAgKi9cbiAgcmVhZG9ubHkgc2VjcmV0OiBzZWNyZXRzbWFuYWdlci5JU2VjcmV0O1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGNvbm5uZWN0aW9ucy5cbiAgICovXG4gIHJlYWRvbmx5IGNvbm5lY3Rpb25zOiBlYzIuQ29ubmVjdGlvbnM7XG4gIC8qKlxuICAgKiBUaGUgZW5kcG9pbnQgYWRkcmVzcyBmb3IgdGhlIGRhdGFiYXNlLlxuICAgKi9cbiAgcmVhZG9ubHkgZW5kcG9pbnQ6IHN0cmluZztcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzYWUgaWRlbnRpZmllci5cbiAgICovXG4gIHJlYWRvbmx5IGlkZW50aWZpZXI6IHN0cmluZztcbn1cblxuLyoqXG4gKiBSZXByZXNlbnRzIHRoZSBkYXRhYmFzZSBpbnN0YW5jZSBvciBkYXRhYmFzZSBjbHVzdGVyXG4gKi9cbmV4cG9ydCBjbGFzcyBEYXRhYmFzZSBleHRlbmRzIENvbnN0cnVjdCB7XG4gIHJlYWRvbmx5IHZwYzogZWMyLklWcGM7XG4gIHJlYWRvbmx5IGNsdXN0ZXJFbmRwb2ludEhvc3RuYW1lOiBzdHJpbmc7XG4gIHJlYWRvbmx5IGNsdXN0ZXJJZGVudGlmaWVyOiBzdHJpbmc7XG4gIHJlYWRvbmx5IHNlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgcmVhZG9ubHkgY29ubmVjdGlvbnM6IGVjMi5Db25uZWN0aW9ucztcbiAgcHJpdmF0ZSByZWFkb25seSBfbXlzcWxMaXN0ZW5lclBvcnQ6IG51bWJlciA9IDMzMDY7XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgcHJvcHM6IERhdGFiYXNlUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQpO1xuICAgIHRoaXMudnBjID0gcHJvcHMudnBjO1xuICAgIGxldCBjb25maWc7XG4gICAgaWYgKHByb3BzLmF1cm9yYVNlcnZlcmxlc3MpIHtcbiAgICAgIGNvbmZpZyA9IHRoaXMuX2NyZWF0ZVNlcnZlcmxlc3NDbHVzdGVyKHByb3BzKTtcbiAgICB9IGVsc2UgaWYgKHByb3BzLmF1cm9yYVNlcnZlcmxlc3NWMikge1xuICAgICAgY29uZmlnID0gdGhpcy5fY3JlYXRlU2VydmVybGVzc1YyQ2x1c3Rlcihwcm9wcyk7XG4gICAgfSBlbHNlIGlmIChwcm9wcy5zaW5nbGVEYkluc3RhbmNlKSB7XG4gICAgICBjb25maWcgPSB0aGlzLl9jcmVhdGVSZHNJbnN0YW5jZShwcm9wcyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbmZpZyA9IHRoaXMuX2NyZWF0ZVJkc0NsdXN0ZXIocHJvcHMpO1xuICAgIH1cbiAgICB0aGlzLnNlY3JldCA9IGNvbmZpZy5zZWNyZXQ7XG4gICAgLy8gYWxsb3cgaW50ZXJuYWxseSBmcm9tIHRoZSBzYW1lIHNlY3VyaXR5IGdyb3VwXG4gICAgY29uZmlnLmNvbm5lY3Rpb25zLmFsbG93SW50ZXJuYWxseShlYzIuUG9ydC50Y3AodGhpcy5fbXlzcWxMaXN0ZW5lclBvcnQpKTtcbiAgICAvLyBhbGxvdyBmcm9tIHRoZSB3aG9sZSB2cGMgY2lkclxuICAgIGNvbmZpZy5jb25uZWN0aW9ucy5hbGxvd0Zyb20oZWMyLlBlZXIuaXB2NChwcm9wcy52cGMudnBjQ2lkckJsb2NrKSwgZWMyLlBvcnQudGNwKHRoaXMuX215c3FsTGlzdGVuZXJQb3J0KSk7XG4gICAgdGhpcy5jbHVzdGVyRW5kcG9pbnRIb3N0bmFtZSA9IGNvbmZpZy5lbmRwb2ludDtcbiAgICB0aGlzLmNsdXN0ZXJJZGVudGlmaWVyID0gY29uZmlnLmlkZW50aWZpZXI7XG4gICAgdGhpcy5jb25uZWN0aW9ucyA9IGNvbmZpZy5jb25uZWN0aW9ucztcbiAgICBwcmludE91dHB1dCh0aGlzLCAnREJTZWNyZXRBcm4nLCBjb25maWcuc2VjcmV0LnNlY3JldEFybik7XG4gICAgcHJpbnRPdXRwdXQodGhpcywgJ2NsdXN0ZXJFbmRwb2ludEhvc3RuYW1lJywgdGhpcy5jbHVzdGVyRW5kcG9pbnRIb3N0bmFtZSk7XG4gICAgcHJpbnRPdXRwdXQodGhpcywgJ2NsdXN0ZXJJZGVudGlmaWVyJywgdGhpcy5jbHVzdGVySWRlbnRpZmllcik7XG4gIH1cbiAgcHJpdmF0ZSBfY3JlYXRlUmRzSW5zdGFuY2UocHJvcHM6IERhdGFiYXNlUHJvcHMpOiBEYXRhYmFzZUNvbmZpZyB7XG4gICAgY29uc3QgZGJJbnN0YW5jZSA9IG5ldyByZHMuRGF0YWJhc2VJbnN0YW5jZSh0aGlzLCAnREJJbnN0YW5jZScsIHtcbiAgICAgIHZwYzogcHJvcHMudnBjLFxuICAgICAgZGF0YWJhc2VOYW1lOiAna2V5Y2xvYWsnLFxuICAgICAgdnBjU3VibmV0czogcHJvcHMuZGF0YWJhc2VTdWJuZXRzLFxuICAgICAgZW5naW5lOiBwcm9wcy5pbnN0YW5jZUVuZ2luZSA/PyByZHMuRGF0YWJhc2VJbnN0YW5jZUVuZ2luZS5teXNxbCh7XG4gICAgICAgIHZlcnNpb246IHJkcy5NeXNxbEVuZ2luZVZlcnNpb24uVkVSXzhfMF8yMSxcbiAgICAgIH0pLFxuICAgICAgc3RvcmFnZUVuY3J5cHRlZDogdHJ1ZSxcbiAgICAgIGJhY2t1cFJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uID8/IGNkay5EdXJhdGlvbi5kYXlzKDcpLFxuICAgICAgY3JlZGVudGlhbHM6IHJkcy5DcmVkZW50aWFscy5mcm9tR2VuZXJhdGVkU2VjcmV0KCdhZG1pbicpLFxuICAgICAgaW5zdGFuY2VUeXBlOiBwcm9wcy5pbnN0YW5jZVR5cGUgPz8gbmV3IGVjMi5JbnN0YW5jZVR5cGUoJ3I1LmxhcmdlJyksXG4gICAgICBwYXJhbWV0ZXJHcm91cDogcmRzLlBhcmFtZXRlckdyb3VwLmZyb21QYXJhbWV0ZXJHcm91cE5hbWUodGhpcywgJ1BhcmFtZXRlckdyb3VwJywgJ2RlZmF1bHQubXlzcWw4LjAnKSxcbiAgICAgIGRlbGV0aW9uUHJvdGVjdGlvbjogZmFsc2UsXG4gICAgICByZW1vdmFsUG9saWN5OiBwcm9wcy5yZW1vdmFsUG9saWN5ID8/IGNkay5SZW1vdmFsUG9saWN5LlJFVEFJTixcbiAgICB9KTtcbiAgICByZXR1cm4ge1xuICAgICAgY29ubmVjdGlvbnM6IGRiSW5zdGFuY2UuY29ubmVjdGlvbnMsXG4gICAgICBlbmRwb2ludDogZGJJbnN0YW5jZS5kYkluc3RhbmNlRW5kcG9pbnRBZGRyZXNzLFxuICAgICAgaWRlbnRpZmllcjogZGJJbnN0YW5jZS5pbnN0YW5jZUlkZW50aWZpZXIsXG4gICAgICBzZWNyZXQ6IGRiSW5zdGFuY2Uuc2VjcmV0ISxcbiAgICB9O1xuICB9XG4gIC8vIGNyZWF0ZSBhIFJEUyBmb3IgTXlTUUwgREIgY2x1c3RlclxuICBwcml2YXRlIF9jcmVhdGVSZHNDbHVzdGVyKHByb3BzOiBEYXRhYmFzZVByb3BzKTogRGF0YWJhc2VDb25maWcge1xuICAgIGNvbnN0IGRiQ2x1c3RlciA9IG5ldyByZHMuRGF0YWJhc2VDbHVzdGVyKHRoaXMsICdEQkNsdXN0ZXInLCB7XG4gICAgICBlbmdpbmU6IHByb3BzLmNsdXN0ZXJFbmdpbmUgPz8gcmRzLkRhdGFiYXNlQ2x1c3RlckVuZ2luZS5hdXJvcmFNeXNxbCh7XG4gICAgICAgIHZlcnNpb246IHJkcy5BdXJvcmFNeXNxbEVuZ2luZVZlcnNpb24uVkVSXzJfMDlfMSxcbiAgICAgIH0pLFxuICAgICAgZGVmYXVsdERhdGFiYXNlTmFtZTogJ2tleWNsb2FrJyxcbiAgICAgIGRlbGV0aW9uUHJvdGVjdGlvbjogZmFsc2UsXG4gICAgICBjcmVkZW50aWFsczogcmRzLkNyZWRlbnRpYWxzLmZyb21HZW5lcmF0ZWRTZWNyZXQoJ2FkbWluJyksXG4gICAgICBpbnN0YW5jZVByb3BzOiB7XG4gICAgICAgIHZwYzogcHJvcHMudnBjLFxuICAgICAgICB2cGNTdWJuZXRzOiBwcm9wcy5kYXRhYmFzZVN1Ym5ldHMsXG4gICAgICAgIGluc3RhbmNlVHlwZTogcHJvcHMuaW5zdGFuY2VUeXBlID8/IG5ldyBlYzIuSW5zdGFuY2VUeXBlKCdyNS5sYXJnZScpLFxuICAgICAgfSxcbiAgICAgIHBhcmFtZXRlckdyb3VwOiByZHMuUGFyYW1ldGVyR3JvdXAuZnJvbVBhcmFtZXRlckdyb3VwTmFtZSh0aGlzLCAnUGFyYW1ldGVyR3JvdXAnLCAnZGVmYXVsdC5hdXJvcmEtbXlzcWw4LjAnKSxcbiAgICAgIGJhY2t1cDoge1xuICAgICAgICByZXRlbnRpb246IHByb3BzLmJhY2t1cFJldGVudGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cyg3KSxcbiAgICAgIH0sXG4gICAgICBzdG9yYWdlRW5jcnlwdGVkOiB0cnVlLFxuICAgICAgcmVtb3ZhbFBvbGljeTogcHJvcHMucmVtb3ZhbFBvbGljeSA/PyBjZGsuUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgfSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGNvbm5lY3Rpb25zOiBkYkNsdXN0ZXIuY29ubmVjdGlvbnMsXG4gICAgICBlbmRwb2ludDogZGJDbHVzdGVyLmNsdXN0ZXJFbmRwb2ludC5ob3N0bmFtZSxcbiAgICAgIGlkZW50aWZpZXI6IGRiQ2x1c3Rlci5jbHVzdGVySWRlbnRpZmllcixcbiAgICAgIHNlY3JldDogZGJDbHVzdGVyLnNlY3JldCEsXG4gICAgfTtcbiAgfVxuICBwcml2YXRlIF9jcmVhdGVTZXJ2ZXJsZXNzQ2x1c3Rlcihwcm9wczogRGF0YWJhc2VQcm9wcyk6IERhdGFiYXNlQ29uZmlnIHtcbiAgICBjb25zdCBkYkNsdXN0ZXIgPSBuZXcgcmRzLlNlcnZlcmxlc3NDbHVzdGVyKHRoaXMsICdBdXJvcmFTZXJ2ZXJsZXNzQ2x1c3RlcicsIHtcbiAgICAgIGVuZ2luZTogcmRzLkRhdGFiYXNlQ2x1c3RlckVuZ2luZS5BVVJPUkFfTVlTUUwsXG4gICAgICB2cGM6IHByb3BzLnZwYyxcbiAgICAgIGRlZmF1bHREYXRhYmFzZU5hbWU6ICdrZXljbG9haycsXG4gICAgICB2cGNTdWJuZXRzOiBwcm9wcy5kYXRhYmFzZVN1Ym5ldHMsXG4gICAgICBjcmVkZW50aWFsczogcmRzLkNyZWRlbnRpYWxzLmZyb21HZW5lcmF0ZWRTZWNyZXQoJ2FkbWluJyksXG4gICAgICBiYWNrdXBSZXRlbnRpb246IHByb3BzLmJhY2t1cFJldGVudGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cyg3KSxcbiAgICAgIGRlbGV0aW9uUHJvdGVjdGlvbjogZmFsc2UsXG4gICAgICByZW1vdmFsUG9saWN5OiBwcm9wcy5yZW1vdmFsUG9saWN5ID8/IGNkay5SZW1vdmFsUG9saWN5LlJFVEFJTixcbiAgICAgIHBhcmFtZXRlckdyb3VwOiByZHMuUGFyYW1ldGVyR3JvdXAuZnJvbVBhcmFtZXRlckdyb3VwTmFtZSh0aGlzLCAnUGFyYW1ldGVyR3JvdXAnLCAnZGVmYXVsdC5hdXJvcmEtbXlzcWw4LjAnKSxcbiAgICB9KTtcbiAgICByZXR1cm4ge1xuICAgICAgY29ubmVjdGlvbnM6IGRiQ2x1c3Rlci5jb25uZWN0aW9ucyxcbiAgICAgIGVuZHBvaW50OiBkYkNsdXN0ZXIuY2x1c3RlckVuZHBvaW50Lmhvc3RuYW1lLFxuICAgICAgaWRlbnRpZmllcjogZGJDbHVzdGVyLmNsdXN0ZXJJZGVudGlmaWVyLFxuICAgICAgc2VjcmV0OiBkYkNsdXN0ZXIuc2VjcmV0ISxcbiAgICB9O1xuICB9XG4gIC8vIGNyZWF0ZSBhIFJEUyBmb3IgTXlTUUwgREIgY2x1c3RlciB3aXRoIEF1cm9yYSBTZXJ2ZXJsZXNzIHYyXG4gIHByaXZhdGUgX2NyZWF0ZVNlcnZlcmxlc3NWMkNsdXN0ZXIocHJvcHM6IERhdGFiYXNlUHJvcHMpOiBEYXRhYmFzZUNvbmZpZyB7XG4gICAgY29uc3QgZGJDbHVzdGVyID0gbmV3IHJkcy5EYXRhYmFzZUNsdXN0ZXIodGhpcywgJ0RCQ2x1c3RlcicsIHtcbiAgICAgIGVuZ2luZTogcHJvcHMuY2x1c3RlckVuZ2luZSA/PyByZHMuRGF0YWJhc2VDbHVzdGVyRW5naW5lLmF1cm9yYU15c3FsKHtcbiAgICAgICAgdmVyc2lvbjogcmRzLkF1cm9yYU15c3FsRW5naW5lVmVyc2lvbi5WRVJfM18wMl8wLFxuICAgICAgfSksXG4gICAgICBkZWZhdWx0RGF0YWJhc2VOYW1lOiAna2V5Y2xvYWsnLFxuICAgICAgZGVsZXRpb25Qcm90ZWN0aW9uOiBmYWxzZSxcbiAgICAgIGNyZWRlbnRpYWxzOiByZHMuQ3JlZGVudGlhbHMuZnJvbUdlbmVyYXRlZFNlY3JldCgnYWRtaW4nKSxcbiAgICAgIGluc3RhbmNlUHJvcHM6IHtcbiAgICAgICAgdnBjOiBwcm9wcy52cGMsXG4gICAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgICAgLy8gU3BlY2lmeSBzZXJ2ZXJsZXNzIEluc3RhbmNlIFR5cGVcbiAgICAgICAgaW5zdGFuY2VUeXBlOiBuZXcgZWMyLkluc3RhbmNlVHlwZSgnc2VydmVybGVzcycpLFxuICAgICAgfSxcbiAgICAgIC8vIFNldCBkZWZhdWx0IHBhcmFtZXRlciBncm91cCBmb3IgQXVyb3JhIE15U1FMIDguMFxuICAgICAgcGFyYW1ldGVyR3JvdXA6IHJkcy5QYXJhbWV0ZXJHcm91cC5mcm9tUGFyYW1ldGVyR3JvdXBOYW1lKHRoaXMsICdQYXJhbWV0ZXJHcm91cCcsICdkZWZhdWx0LmF1cm9yYS1teXNxbDguMCcpLFxuICAgICAgYmFja3VwOiB7XG4gICAgICAgIHJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uID8/IGNkay5EdXJhdGlvbi5kYXlzKDcpLFxuICAgICAgfSxcbiAgICAgIHN0b3JhZ2VFbmNyeXB0ZWQ6IHRydWUsXG4gICAgICByZW1vdmFsUG9saWN5OiBwcm9wcy5yZW1vdmFsUG9saWN5ID8/IGNkay5SZW1vdmFsUG9saWN5LlJFVEFJTixcbiAgICB9KTtcbiAgICAvLyBTZXQgU2VydmVybGVzcyBWMiBTY2FsaW5nIENvbmZpZ3VyYXRpb25cbiAgICAvLyBUT0RPOiBVc2UgY2xlYW5lciB3YXkgdG8gc2V0IHNjYWxpbmcgY29uZmlndXJhdGlvbi5cbiAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vYXdzL2F3cy1jZGsvaXNzdWVzLzIwMTk3XG4gICAgKFxuICAgICAgZGJDbHVzdGVyLm5vZGUuZmluZENoaWxkKCdSZXNvdXJjZScpIGFzIHJkcy5DZm5EQkNsdXN0ZXJcbiAgICApLnNlcnZlcmxlc3NWMlNjYWxpbmdDb25maWd1cmF0aW9uID0ge1xuICAgICAgbWluQ2FwYWNpdHk6IHByb3BzLm1pbkNhcGFjaXR5ID8/IDAuNSxcbiAgICAgIG1heENhcGFjaXR5OiBwcm9wcy5tYXhDYXBhY2l0eSA/PyAxMCxcbiAgICB9O1xuICAgIHJldHVybiB7XG4gICAgICBjb25uZWN0aW9uczogZGJDbHVzdGVyLmNvbm5lY3Rpb25zLFxuICAgICAgZW5kcG9pbnQ6IGRiQ2x1c3Rlci5jbHVzdGVyRW5kcG9pbnQuaG9zdG5hbWUsXG4gICAgICBpZGVudGlmaWVyOiBkYkNsdXN0ZXIuY2x1c3RlcklkZW50aWZpZXIsXG4gICAgICBzZWNyZXQ6IGRiQ2x1c3Rlci5zZWNyZXQhLFxuICAgIH07XG4gIH1cbn1cblxuZXhwb3J0IGludGVyZmFjZSBDb250YWluZXJTZXJ2aWNlUHJvcHMge1xuICAvKipcbiAgICogVGhlIGVudmlyb25tZW50IHZhcmlhYmxlcyB0byBwYXNzIHRvIHRoZSBrZXljbG9hayBjb250YWluZXJcbiAgICovXG4gIHJlYWRvbmx5IGVudj86IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIH07XG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIGZvciB0aGUgY29udGFpbmVyIGltYWdlXG4gICAqL1xuICByZWFkb25seSBrZXljbG9ha1ZlcnNpb246IEtleWNsb2FrVmVyc2lvbjtcbiAgLyoqXG4gICAqIFRoZSBWUEMgZm9yIHRoZSBzZXJ2aWNlXG4gICAqL1xuICByZWFkb25seSB2cGM6IGVjMi5JVnBjO1xuICAvKipcbiAgICogVlBDIHN1Ym5ldHMgZm9yIGtleWNsb2FrIHNlcnZpY2VcbiAgICovXG4gIHJlYWRvbmx5IHByaXZhdGVTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFZQQyBwdWJsaWMgc3VibmV0cyBmb3IgQUxCXG4gICAqL1xuICByZWFkb25seSBwdWJsaWNTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFRoZSBSRFMgZGF0YWJhc2UgZm9yIHRoZSBzZXJ2aWNlXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZTogRGF0YWJhc2U7XG4gIC8qKlxuICAgKiBUaGUgc2VjcmV0cyBtYW5hZ2VyIHNlY3JldCBmb3IgdGhlIGtleWNsb2FrXG4gICAqL1xuICByZWFkb25seSBrZXljbG9ha1NlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgLyoqXG4gICAqIFRoZSBBQ00gY2VydGlmaWNhdGVcbiAgICovXG4gIHJlYWRvbmx5IGNlcnRpZmljYXRlOiBjZXJ0bWdyLklDZXJ0aWZpY2F0ZTtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gY3JlYXRlIHRoZSBiYXN0aW9uIGhvc3RcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGJhc3Rpb24/OiBib29sZWFuO1xuICAvKipcbiAgICogV2hldGhlciB0byBlbmFibGUgdGhlIEVDUyBzZXJ2aWNlIGRlcGxveW1lbnQgY2lyY3VpdCBicmVha2VyXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBjaXJjdWl0QnJlYWtlcj86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBOdW1iZXIgb2Yga2V5Y2xvYWsgbm9kZSBpbiB0aGUgY2x1c3RlclxuICAgKlxuICAgKiBAZGVmYXVsdCAxXG4gICAqL1xuICByZWFkb25seSBub2RlQ291bnQ/OiBudW1iZXI7XG4gIC8qKlxuICAgKiBUaGUgc3RpY2t5IHNlc3Npb24gZHVyYXRpb24gZm9yIHRoZSBrZXljbG9hayB3b3JrbG9hZCB3aXRoIEFMQi5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBvbmUgZGF5XG4gICAqL1xuICByZWFkb25seSBzdGlja2luZXNzQ29va2llRHVyYXRpb24/OiBjZGsuRHVyYXRpb247XG5cbiAgLyoqXG4gICAqIEF1dG9zY2FsaW5nIGZvciB0aGUgRUNTIFNlcnZpY2VcbiAgICpcbiAgICogQGRlZmF1bHQgLSBubyBlY3Mgc2VydmljZSBhdXRvc2NhbGluZ1xuICAgKi9cbiAgcmVhZG9ubHkgYXV0b1NjYWxlVGFzaz86IEF1dG9TY2FsZVRhc2s7XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gcHV0IHRoZSBwdXQgdGhlIGxvYWQgYmFsYW5jZXIgaW4gdGhlIHB1YmxpYyBvciBwcml2YXRlIHN1Ym5ldHNcbiAgICpcbiAgICogQGRlZmF1bHQgdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgaW50ZXJuZXRGYWNpbmc/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBUaGUgaG9zdG5hbWUgdG8gdXNlIGZvciB0aGUga2V5Y2xvYWsgc2VydmVyXG4gICAqL1xuICByZWFkb25seSBob3N0bmFtZT86IHN0cmluZztcblxuXG4gIC8qKlxuICAgKiBPdmVycmlkZXMgdGhlIGRlZmF1bHQgaW1hZ2VcbiAgICpcbiAgICogQGRlZmF1bHQgcXVheS5pby9rZXljbG9hay9rZXljbG9hazoke0tFWUNMT0FLX1ZFUlNJT059XG4gICAqL1xuICByZWFkb25seSBjb250YWluZXJJbWFnZT86IGVjcy5Db250YWluZXJJbWFnZTtcblxuICAvKipcbiAgICogVGhlIG51bWJlciBvZiBjcHUgdW5pdHMgdXNlZCBieSB0aGUgS2V5Y2xvYWsgdGFzay5cbiAgICogWW91IG11c3QgdXNlIG9uZSBvZiB0aGUgZm9sbG93aW5nIHZhbHVlcywgd2hpY2ggZGV0ZXJtaW5lcyB5b3VyIHJhbmdlIG9mIHZhbGlkIHZhbHVlcyBmb3IgdGhlIG1lbW9yeSBwYXJhbWV0ZXI6XG4gICAqIDI1NiAoLjI1IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IDUxMiAoMC41IEdCKSwgMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpXG4gICAqIDUxMiAoLjUgdkNQVSkgLSBBdmFpbGFibGUgbWVtb3J5IHZhbHVlczogMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpLCAzMDcyICgzIEdCKSwgNDA5NiAoNCBHQilcbiAgICogMTAyNCAoMSB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpLCA1MTIwICg1IEdCKSwgNjE0NCAoNiBHQiksIDcxNjggKDcgR0IpLCA4MTkyICg4IEdCKVxuICAgKiAyMDQ4ICgyIHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gNDA5NiAoNCBHQikgYW5kIDE2Mzg0ICgxNiBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKVxuICAgKiA0MDk2ICg0IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gODE5MiAoOCBHQikgYW5kIDMwNzIwICgzMCBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKVxuICAgKiA4MTkyICg4IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gMTYzODQgKDE2IEdCKSBhbmQgNjE0NDAgKDYwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDQwOTYgKDQgR0IpXG4gICAqIDE2Mzg0ICgxNiB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiBCZXR3ZWVuIDMyNzY4ICgzMiBHQikgYW5kIDEyMjg4MCAoMTIwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDgxOTIgKDggR0IpXG4gICAqL1xuICByZWFkb25seSBjcHU6IG51bWJlcjtcblxuICAvKipcbiAgICogVGhlIGFtb3VudCAoaW4gTWlCKSBvZiBtZW1vcnkgdXNlZCBieSB0aGUgdGFzay5cbiAgICogWW91IG11c3QgdXNlIG9uZSBvZiB0aGUgZm9sbG93aW5nIHZhbHVlcywgd2hpY2ggZGV0ZXJtaW5lcyB5b3VyIHJhbmdlIG9mIHZhbGlkIHZhbHVlcyBmb3IgdGhlIGNwdSBwYXJhbWV0ZXI6XG4gICAqIDUxMiAoMC41IEdCKSwgMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDI1NiAoLjI1IHZDUFUpXG4gICAqIDEwMjQgKDEgR0IpLCAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDUxMiAoLjUgdkNQVSlcbiAgICogMjA0OCAoMiBHQiksIDMwNzIgKDMgR0IpLCA0MDk2ICg0IEdCKSwgNTEyMCAoNSBHQiksIDYxNDQgKDYgR0IpLCA3MTY4ICg3IEdCKSwgODE5MiAoOCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMTAyNCAoMSB2Q1BVKVxuICAgKiBCZXR3ZWVuIDQwOTYgKDQgR0IpIGFuZCAxNjM4NCAoMTYgR0IpIGluIGluY3JlbWVudHMgb2YgMTAyNCAoMSBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMjA0OCAoMiB2Q1BVKVxuICAgKiBCZXR3ZWVuIDgxOTIgKDggR0IpIGFuZCAzMDcyMCAoMzAgR0IpIGluIGluY3JlbWVudHMgb2YgMTAyNCAoMSBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogNDA5NiAoNCB2Q1BVKVxuICAgKiBCZXR3ZWVuIDE2Mzg0ICgxNiBHQikgYW5kIDYxNDQwICg2MCBHQikgaW4gaW5jcmVtZW50cyBvZiA0MDk2ICg0IEdCKSAtIEF2YWlsYWJsZSBjcHUgdmFsdWVzOiA4MTkyICg4IHZDUFUpXG4gICAqIEJldHdlZW4gMzI3NjggKDMyIEdCKSBhbmQgMTIyODgwICgxMjAgR0IpIGluIGluY3JlbWVudHMgb2YgODE5MiAoOCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMTYzODQgKDE2IHZDUFUpXG4gICAqL1xuICByZWFkb25seSBtZW1vcnlMaW1pdE1pQjogbnVtYmVyO1xufVxuXG5leHBvcnQgY2xhc3MgQ29udGFpbmVyU2VydmljZSBleHRlbmRzIENvbnN0cnVjdCB7XG4gIHJlYWRvbmx5IHNlcnZpY2U6IGVjcy5GYXJnYXRlU2VydmljZTtcbiAgcmVhZG9ubHkgYXBwbGljYXRpb25Mb2FkQmFsYW5jZXI6IGVsYnYyLkFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyO1xuICAvLyByZWFkb25seSBuZXR3b3JrTG9hZEJhbGFuY2VyOiBlbGJ2Mi5OZXR3b3JrTG9hZEJhbGFuY2VyO1xuICByZWFkb25seSBrZXljbG9ha1VzZXJTZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBDb250YWluZXJTZXJ2aWNlUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQpO1xuXG4gICAgY29uc3QgeyBjcHUsIG1lbW9yeUxpbWl0TWlCIH0gPSBwcm9wcztcblxuICAgIGNvbnN0IHJlZ2lvbiA9IGNkay5TdGFjay5vZih0aGlzKS5yZWdpb247XG4gICAgY29uc3QgY29udGFpbmVyUG9ydCA9IDgwODA7XG4gICAgY29uc3QgY29ubmVjdGlvblN0cmluZyA9IGBqZGJjOm15c3FsOi8vJHtwcm9wcy5kYXRhYmFzZS5jbHVzdGVyRW5kcG9pbnRIb3N0bmFtZX06MzMwNi9rZXljbG9ha2A7XG4gICAgLy8gY29uc3QgcHJvdG9jb2wgPSBlbGJ2Mi5BcHBsaWNhdGlvblByb3RvY29sLkhUVFA7XG4gICAgY29uc3QgZW50cnlQb2ludCA9IFsnL29wdC9rZXljbG9hay9iaW4va2Muc2gnLCAnc3RhcnQnLCAnLS1vcHRpbWl6ZWQnXTtcbiAgICBjb25zdCBzM1BpbmdCdWNrZXQgPSBuZXcgczMuQnVja2V0KHRoaXMsICdrZXljbG9ha19zM19waW5nJyk7XG4gICAgY29uc3QgaW1hZ2UgPSBwcm9wcy5jb250YWluZXJJbWFnZSA/PyBlY3MuQ29udGFpbmVySW1hZ2UuZnJvbVJlZ2lzdHJ5KHRoaXMuZ2V0S2V5Q2xvYWtEb2NrZXJJbWFnZVVyaShwcm9wcy5rZXljbG9ha1ZlcnNpb24udmVyc2lvbikpO1xuICAgIGNvbnN0IHNlY3JldHM6IHtba2V5OiBzdHJpbmddOiBjZGsuYXdzX2Vjcy5TZWNyZXR9ID0ge1xuICAgICAgS0NfREJfUEFTU1dPUkQ6IGVjcy5TZWNyZXQuZnJvbVNlY3JldHNNYW5hZ2VyKHByb3BzLmRhdGFiYXNlLnNlY3JldCwgJ3Bhc3N3b3JkJyksXG4gICAgICBLRVlDTE9BS19BRE1JTjogZWNzLlNlY3JldC5mcm9tU2VjcmV0c01hbmFnZXIocHJvcHMua2V5Y2xvYWtTZWNyZXQsICd1c2VybmFtZScpLFxuICAgICAgS0VZQ0xPQUtfQURNSU5fUEFTU1dPUkQ6IGVjcy5TZWNyZXQuZnJvbVNlY3JldHNNYW5hZ2VyKHByb3BzLmtleWNsb2FrU2VjcmV0LCAncGFzc3dvcmQnKSxcbiAgICB9O1xuICAgIGNvbnN0IHBvcnRNYXBwaW5nczogZWNzLlBvcnRNYXBwaW5nW10gPSBbXG4gICAgICB7IGNvbnRhaW5lclBvcnQ6IGNvbnRhaW5lclBvcnQgfSwgLy8gd2ViIHBvcnRcbiAgICAgIHsgY29udGFpbmVyUG9ydDogNzgwMCB9LCAvLyBqZ3JvdXBzLXMzXG4gICAgICB7IGNvbnRhaW5lclBvcnQ6IDU3ODAwIH0sIC8vIGpncm91cHMtczMtZmRcbiAgICBdO1xuICAgIGNvbnN0IHZwYyA9IHByb3BzLnZwYztcbiAgICBjb25zdCBjbHVzdGVyID0gbmV3IGVjcy5DbHVzdGVyKHRoaXMsICdDbHVzdGVyJywgeyB2cGMsIGNvbnRhaW5lckluc2lnaHRzOiB0cnVlIH0pO1xuICAgIGNsdXN0ZXIubm9kZS5hZGREZXBlbmRlbmN5KHByb3BzLmRhdGFiYXNlKTtcbiAgICBjb25zdCBleGVjdXRpb25Sb2xlID0gbmV3IGlhbS5Sb2xlKHRoaXMsICdUYXNrUm9sZScsIHtcbiAgICAgIGFzc3VtZWRCeTogbmV3IGlhbS5Db21wb3NpdGVQcmluY2lwYWwoXG4gICAgICAgIG5ldyBpYW0uU2VydmljZVByaW5jaXBhbCgnZWNzLmFtYXpvbmF3cy5jb20nKSxcbiAgICAgICAgbmV3IGlhbS5TZXJ2aWNlUHJpbmNpcGFsKCdlY3MtdGFza3MuYW1hem9uYXdzLmNvbScpLFxuICAgICAgKSxcbiAgICB9KTtcbiAgICBjb25zdCB0YXNrRGVmaW5pdGlvbiA9IG5ldyBlY3MuRmFyZ2F0ZVRhc2tEZWZpbml0aW9uKHRoaXMsICdUYXNrRGVmJywge1xuICAgICAgY3B1LFxuICAgICAgbWVtb3J5TGltaXRNaUIsXG4gICAgICBleGVjdXRpb25Sb2xlLFxuICAgIH0pO1xuXG4gICAgY29uc3QgbG9nR3JvdXAgPSBuZXcgbG9ncy5Mb2dHcm91cCh0aGlzLCAnTG9nR3JvdXAnLCB7XG4gICAgICByZXRlbnRpb246IGxvZ3MuUmV0ZW50aW9uRGF5cy5PTkVfTU9OVEgsXG4gICAgICByZW1vdmFsUG9saWN5OiBjZGsuUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgfSk7XG5cbiAgICBjb25zdCBzM1VzZXIgPSBuZXcgaWFtLlVzZXIodGhpcywgJ1MzS2V5Y2xvYWtVc2VyJyk7XG4gICAgY29uc3QgYWNjZXNzS2V5ID0gbmV3IGlhbS5BY2Nlc3NLZXkodGhpcywgJ1MzS2V5Y2xvYWtVc2VyQWNjZXNzS2V5JywgeyB1c2VyOiBzM1VzZXIgfSk7XG4gICAgdGhpcy5rZXljbG9ha1VzZXJTZWNyZXQgPSBuZXcgc2VjcmV0c21hbmFnZXIuU2VjcmV0KHRoaXMsICdTM0tleWNsb2FrVXNlclNlY3JldCcsIHtcbiAgICAgIHNlY3JldFN0cmluZ1ZhbHVlOiBhY2Nlc3NLZXkuc2VjcmV0QWNjZXNzS2V5LFxuICAgIH0pO1xuICAgIHMzUGluZ0J1Y2tldCEuZ3JhbnRSZWFkV3JpdGUoczNVc2VyKTtcblxuICAgIGNvbnN0IGVudmlyb25tZW50OiB7W2tleTogc3RyaW5nXTogc3RyaW5nfSA9IHtcbiAgICAgIEpBVkFfT1BUU19BUFBFTkQ6IGBcbiAgICAgIC1Eamdyb3Vwcy5zMy5yZWdpb25fbmFtZT0ke3JlZ2lvbn1cbiAgICAgIC1Eamdyb3Vwcy5zMy5idWNrZXRfbmFtZT0ke3MzUGluZ0J1Y2tldCEuYnVja2V0TmFtZX1cbiAgICAgIC1Eamdyb3Vwcy5zMy5hY2Nlc3Nfa2V5PSR7YWNjZXNzS2V5LmFjY2Vzc0tleUlkfVxuICAgICAgLURqZ3JvdXBzLnMzLnNlY3JldF9hY2Nlc3Nfa2V5PSR7YWNjZXNzS2V5LnNlY3JldEFjY2Vzc0tleX1cbiAgICAgIGAucmVwbGFjZSgnXFxyXFxuJywgJycpLnJlcGxhY2UoJ1xcbicsICcnKS5yZXBsYWNlKC9cXHMrL2csICcgJyksXG4gICAgICAvLyBXZSBoYXZlIHNlbGVjdGVkIHRoZSBjYWNoZSBzdGFjayBvZiAnZWMyJyB3aGljaCB1c2VzIFMzX1BJTkcgdW5kZXIgdGhlIGhvb2RcbiAgICAgIC8vIFRoaXMgaXMgdGhlIEFXUyBuYXRpdmUgY2x1c3RlciBkaXNjb3ZlcnkgYXBwcm9hY2ggZm9yIGNhY2hpbmdcbiAgICAgIC8vIFNlZTogaHR0cHM6Ly93d3cua2V5Y2xvYWsub3JnL3NlcnZlci9jYWNoaW5nI190cmFuc3BvcnRfc3RhY2tzXG4gICAgICBLQ19DQUNIRV9TVEFDSzogJ2VjMicsXG4gICAgICBLQ19EQjogJ215c3FsJyxcbiAgICAgIEtDX0RCX1VSTF9EQVRBQkFTRTogJ2tleWNsb2FrJyxcbiAgICAgIEtDX0RCX1VSTDogY29ubmVjdGlvblN0cmluZyxcbiAgICAgIEtDX0RCX1VSTF9QT1JUOiAnMzMwNicsXG4gICAgICBLQ19EQl9VU0VSTkFNRTogJ2FkbWluJyxcbiAgICAgIEtDX0hPU1ROQU1FOiBwcm9wcy5ob3N0bmFtZSEsXG4gICAgICBLQ19IT1NUTkFNRV9TVFJJQ1RfQkFDS0NIQU5ORUw6ICd0cnVlJyxcbiAgICAgIEtDX1BST1hZOiAnZWRnZScsXG4gICAgICBLQ19IRUFMVEhfRU5BQkxFRDogJ3RydWUnLFxuICAgIH07XG5cbiAgICBjb25zdCBrYyA9IHRhc2tEZWZpbml0aW9uLmFkZENvbnRhaW5lcigna2V5Y2xvYWsnLCB7XG4gICAgICBpbWFnZSxcbiAgICAgIGVudHJ5UG9pbnQsXG4gICAgICBlbnZpcm9ubWVudDogT2JqZWN0LmFzc2lnbihlbnZpcm9ubWVudCwgcHJvcHMuZW52KSxcbiAgICAgIHNlY3JldHMsXG4gICAgICBsb2dnaW5nOiBlY3MuTG9nRHJpdmVycy5hd3NMb2dzKHtcbiAgICAgICAgc3RyZWFtUHJlZml4OiAna2V5Y2xvYWsnLFxuICAgICAgICBsb2dHcm91cCxcbiAgICAgIH0pLFxuICAgIH0pO1xuICAgIGtjLmFkZFBvcnRNYXBwaW5ncyguLi5wb3J0TWFwcGluZ3MpO1xuXG4gICAgLy8gd2UgbmVlZCBleHRyYSBwcml2aWxlZ2VzIHRvIGZldGNoIGtleWNsb2FrIGRvY2tlciBpbWFnZXMgZnJvbSBDaGluYSBtaXJyb3Igc2l0ZVxuICAgIHRhc2tEZWZpbml0aW9uLmV4ZWN1dGlvblJvbGU/LmFkZE1hbmFnZWRQb2xpY3koaWFtLk1hbmFnZWRQb2xpY3kuZnJvbUF3c01hbmFnZWRQb2xpY3lOYW1lKCdBbWF6b25FQzJDb250YWluZXJSZWdpc3RyeVJlYWRPbmx5JykpO1xuXG4gICAgdGhpcy5zZXJ2aWNlID0gbmV3IGVjcy5GYXJnYXRlU2VydmljZSh0aGlzLCAnU2VydmljZScsIHtcbiAgICAgIGNsdXN0ZXIsXG4gICAgICB0YXNrRGVmaW5pdGlvbixcbiAgICAgIGNpcmN1aXRCcmVha2VyOiBwcm9wcy5jaXJjdWl0QnJlYWtlciA/IHsgcm9sbGJhY2s6IHRydWUgfSA6IHVuZGVmaW5lZCxcbiAgICAgIGRlc2lyZWRDb3VudDogcHJvcHMubm9kZUNvdW50ID8/IDIsXG4gICAgICBoZWFsdGhDaGVja0dyYWNlUGVyaW9kOiBjZGsuRHVyYXRpb24uc2Vjb25kcygxMjApLFxuICAgIH0pO1xuXG4gICAgdGhpcy5zZXJ2aWNlLmNvbm5lY3Rpb25zLmFsbG93RnJvbSh0aGlzLnNlcnZpY2UuY29ubmVjdGlvbnMsIGVjMi5Qb3J0LnRjcCg3ODAwKSwgJ2tjIGpncm91cHMtdGNwJyk7XG4gICAgdGhpcy5zZXJ2aWNlLmNvbm5lY3Rpb25zLmFsbG93RnJvbSh0aGlzLnNlcnZpY2UuY29ubmVjdGlvbnMsIGVjMi5Qb3J0LnRjcCg1NzgwMCksICdrYyBqZ3JvdXBzLXRjcC1mZCcpO1xuICAgIHMzUGluZ0J1Y2tldCEuZ3JhbnRSZWFkV3JpdGUodGFza0RlZmluaXRpb24udGFza1JvbGUpO1xuXG4gICAgaWYgKHByb3BzLmF1dG9TY2FsZVRhc2spIHtcbiAgICAgIGNvbnN0IG1pbkNhcGFjaXR5ID0gcHJvcHMuYXV0b1NjYWxlVGFzay5taW4gPz8gcHJvcHMubm9kZUNvdW50ID8/IDI7XG4gICAgICBjb25zdCBzY2FsaW5nID0gdGhpcy5zZXJ2aWNlLmF1dG9TY2FsZVRhc2tDb3VudCh7XG4gICAgICAgIG1pbkNhcGFjaXR5LFxuICAgICAgICBtYXhDYXBhY2l0eTogcHJvcHMuYXV0b1NjYWxlVGFzay5tYXggPz8gbWluQ2FwYWNpdHkgKyA1LFxuICAgICAgfSk7XG4gICAgICBzY2FsaW5nLnNjYWxlT25DcHVVdGlsaXphdGlvbignQ3B1U2NhbGluZycsIHtcbiAgICAgICAgdGFyZ2V0VXRpbGl6YXRpb25QZXJjZW50OiBwcm9wcy5hdXRvU2NhbGVUYXNrLnRhcmdldENwdVV0aWxpemF0aW9uID8/IDc1LFxuICAgICAgfSk7XG4gICAgfTtcblxuICAgIC8vIGxpc3RlbmVyIHByb3RvY29sICdUTFMnIGlzIG5vdCBzdXBwb3J0ZWQgd2l0aCBhIHRhcmdldCBncm91cCB3aXRoIHRoZSB0YXJnZXQtdHlwZSAnQUxCJ1xuXG4gICAgdGhpcy5hcHBsaWNhdGlvbkxvYWRCYWxhbmNlciA9IG5ldyBlbGJ2Mi5BcHBsaWNhdGlvbkxvYWRCYWxhbmNlcih0aGlzLCAnQUxCJywge1xuICAgICAgdnBjLFxuICAgICAgdnBjU3VibmV0czogcHJvcHMucHVibGljU3VibmV0cyxcbiAgICAgIGludGVybmV0RmFjaW5nOiB0cnVlLFxuICAgICAgLy8gdnBjU3VibmV0czogcHJvcHMuaW50ZXJuZXRGYWNpbmcgPyBwcm9wcy5wdWJsaWNTdWJuZXRzIDogcHJvcHMucHJpdmF0ZVN1Ym5ldHMsXG4gICAgICAvLyBpbnRlcm5ldEZhY2luZzogcHJvcHMuaW50ZXJuZXRGYWNpbmcsXG4gICAgfSk7XG4gICAgcHJpbnRPdXRwdXQodGhpcywgJ0VuZHBvaW50VVJMJywgYGh0dHBzOi8vJHt0aGlzLmFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyLmxvYWRCYWxhbmNlckRuc05hbWV9YCk7XG5cbiAgICBjb25zdCBsaXN0ZW5lciA9IHRoaXMuYXBwbGljYXRpb25Mb2FkQmFsYW5jZXIuYWRkTGlzdGVuZXIoJ0FMQl9IdHRwc0xpc3RlbmVyJywge1xuICAgICAgcHJvdG9jb2w6IGVsYnYyLkFwcGxpY2F0aW9uUHJvdG9jb2wuSFRUUFMsXG4gICAgICBjZXJ0aWZpY2F0ZXM6IFt7IGNlcnRpZmljYXRlQXJuOiBwcm9wcy5jZXJ0aWZpY2F0ZS5jZXJ0aWZpY2F0ZUFybiB9XSxcbiAgICB9KTtcbiAgICAvLyBcIklmIHRoZSB0YXJnZXQgdHlwZSBpcyBBTEIsIHRoZSB0YXJnZXQgbXVzdCBoYXZlIGF0IGxlYXN0IG9uZSBsaXN0ZW5lciB0aGF0IG1hdGNoZXMgdGhlIHRhcmdldCBncm91cCBwb3J0IG9yIGFueSBzcGVjaWZpZWQgcG9ydCBvdmVycmlkZXNcbiAgICBsaXN0ZW5lci5hZGRUYXJnZXRzKCdFQ1NUYXJnZXQnLCB7XG4gICAgICBwcm90b2NvbDogZWxidjIuQXBwbGljYXRpb25Qcm90b2NvbC5IVFRQLFxuICAgICAgc2xvd1N0YXJ0OiBjZGsuRHVyYXRpb24uc2Vjb25kcyg2MCksXG4gICAgICBzdGlja2luZXNzQ29va2llRHVyYXRpb246IHByb3BzLnN0aWNraW5lc3NDb29raWVEdXJhdGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cygxKSxcbiAgICAgIHRhcmdldHM6IFt0aGlzLnNlcnZpY2VdLFxuICAgICAgaGVhbHRoQ2hlY2s6IHtcbiAgICAgICAgaGVhbHRoeVRocmVzaG9sZENvdW50OiAzLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIGFsbG93IHRhc2sgZXhlY3V0aW9uIHJvbGUgdG8gcmVhZCB0aGUgc2VjcmV0c1xuICAgIHByb3BzLmRhdGFiYXNlLnNlY3JldC5ncmFudFJlYWQodGFza0RlZmluaXRpb24uZXhlY3V0aW9uUm9sZSEpO1xuICAgIHByb3BzLmtleWNsb2FrU2VjcmV0LmdyYW50UmVhZCh0YXNrRGVmaW5pdGlvbi5leGVjdXRpb25Sb2xlISk7XG5cbiAgICAvLyBhbGxvdyBlY3MgdGFzayBjb25uZWN0IHRvIGRhdGFiYXNlXG4gICAgcHJvcHMuZGF0YWJhc2UuY29ubmVjdGlvbnMuYWxsb3dEZWZhdWx0UG9ydEZyb20odGhpcy5zZXJ2aWNlKTtcblxuXG4gICAgLy8gY3JlYXRlIGEgYmFzdGlvbiBob3N0XG4gICAgaWYgKHByb3BzLmJhc3Rpb24gPT09IHRydWUpIHtcbiAgICAgIGNvbnN0IGJhc3QgPSBuZXcgZWMyLkJhc3Rpb25Ib3N0TGludXgodGhpcywgJ0Jhc3QnLCB7XG4gICAgICAgIHZwYyxcbiAgICAgICAgaW5zdGFuY2VUeXBlOiBuZXcgZWMyLkluc3RhbmNlVHlwZSgndDMuc21hbGwnKSxcbiAgICAgIH0pO1xuICAgICAgcHJvcHMuZGF0YWJhc2UuY29ubmVjdGlvbnMuYWxsb3dEZWZhdWx0UG9ydEZyb20oYmFzdCk7XG4gICAgfVxuICB9XG4gIHByaXZhdGUgZ2V0SW1hZ2VVcmlGcm9tTWFwKG1hcDogZG9ja2VySW1hZ2VNYXAsIHZlcnNpb246IHN0cmluZywgaWQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgY29uc3Qgc3RhY2sgPSBjZGsuU3RhY2sub2YodGhpcyk7XG4gICAgaWYgKGNkay5Ub2tlbi5pc1VucmVzb2x2ZWQoc3RhY2sucmVnaW9uKSkge1xuICAgICAgY29uc3QgbWFwcGluZzogeyBbazE6IHN0cmluZ106IHsgW2syOiBzdHJpbmddOiBhbnkgfSB9ID0ge307XG4gICAgICBmb3IgKGxldCBbcGFydGl0aW9uLCB1cmldIG9mIE9iamVjdC5lbnRyaWVzKG1hcCkpIHtcbiAgICAgICAgdXJpICs9IHZlcnNpb247XG4gICAgICAgIG1hcHBpbmdbcGFydGl0aW9uXSA9IHsgdXJpIH07XG4gICAgICB9XG4gICAgICBjb25zdCBpbWFnZU1hcCA9IG5ldyBjZGsuQ2ZuTWFwcGluZyh0aGlzLCBpZCwgeyBtYXBwaW5nIH0pO1xuICAgICAgcmV0dXJuIGltYWdlTWFwLmZpbmRJbk1hcChjZGsuQXdzLlBBUlRJVElPTiwgJ3VyaScpO1xuICAgIH0gZWxzZSB7XG4gICAgICBpZiAoc3RhY2sucmVnaW9uLnN0YXJ0c1dpdGgoJ2NuLScpKSB7XG4gICAgICAgIHJldHVybiBtYXBbJ2F3cy1jbiddICs9IHZlcnNpb247XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gbWFwLmF3cyArPSB2ZXJzaW9uO1xuICAgICAgfVxuICAgIH1cbiAgfVxuICBwcml2YXRlIGdldEtleUNsb2FrRG9ja2VySW1hZ2VVcmkodmVyc2lvbjogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5nZXRJbWFnZVVyaUZyb21NYXAoS0VZQ0xPQUtfRE9DS0VSX0lNQUdFX1VSSV9NQVAsIHZlcnNpb24sICdLZXljbG9ha0ltYWdlTWFwJyk7XG4gIH1cbn1cblxuLyoqXG4gKiBDcmVhdGUgb3IgaW1wb3J0IFZQQ1xuICogQHBhcmFtIHNjb3BlIHRoZSBjZGsgc2NvcGVcbiAqL1xuZnVuY3Rpb24gZ2V0T3JDcmVhdGVWcGMoc2NvcGU6IENvbnN0cnVjdCk6IGVjMi5JVnBjIHtcbiAgLy8gdXNlIGFuIGV4aXN0aW5nIHZwYyBvciBjcmVhdGUgYSBuZXcgb25lXG4gIHJldHVybiBzY29wZS5ub2RlLnRyeUdldENvbnRleHQoJ3VzZV9kZWZhdWx0X3ZwYycpID09PSAnMScgP1xuICAgIGVjMi5WcGMuZnJvbUxvb2t1cChzY29wZSwgJ1ZwYycsIHsgaXNEZWZhdWx0OiB0cnVlIH0pIDpcbiAgICBzY29wZS5ub2RlLnRyeUdldENvbnRleHQoJ3VzZV92cGNfaWQnKSA/XG4gICAgICBlYzIuVnBjLmZyb21Mb29rdXAoc2NvcGUsICdWcGMnLCB7IHZwY0lkOiBzY29wZS5ub2RlLnRyeUdldENvbnRleHQoJ3VzZV92cGNfaWQnKSB9KSA6XG4gICAgICBuZXcgZWMyLlZwYyhzY29wZSwgJ1ZwYycsIHsgbWF4QXpzOiAzLCBuYXRHYXRld2F5czogMSB9KTtcbn1cblxuZnVuY3Rpb24gcHJpbnRPdXRwdXQoc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywga2V5OiBzdHJpbmcgfCBudW1iZXIpIHtcbiAgbmV3IGNkay5DZm5PdXRwdXQoc2NvcGUsIGlkLCB7IHZhbHVlOiBTdHJpbmcoa2V5KSB9KTtcbn1cbiJdfQ==