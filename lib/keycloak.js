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
        const { cpu = 2048, memoryLimitMiB = 4096 } = props;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoia2V5Y2xvYWsuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMva2V5Y2xvYWsudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSxtQ0FBbUM7QUFDbkMsNkNBU3FCO0FBQ3JCLDJDQUF1QztBQUV2Qyw4Q0FBOEM7QUFDOUMsc0hBQXNIO0FBQ3RILE1BQU0sbUNBQW1DLEdBQUc7SUFDMUMsV0FBVztJQUNYLFdBQVc7SUFDWCxXQUFXO0lBQ1gsV0FBVztJQUNYLFlBQVk7SUFDWixnQkFBZ0I7SUFDaEIsZ0JBQWdCO0lBQ2hCLGdCQUFnQjtJQUNoQixnQkFBZ0I7SUFDaEIsY0FBYztJQUNkLGNBQWM7SUFDZCxXQUFXO0lBQ1gsV0FBVztJQUNYLFdBQVc7SUFDWCxnQkFBZ0I7Q0FDakIsQ0FBQztBQUVGOztHQUVHO0FBQ0gsTUFBYSxlQUFlO0lBNkQxQjs7O09BR0c7SUFDSCxZQUFvQyxPQUFlO1FBQWYsWUFBTyxHQUFQLE9BQU8sQ0FBUTtJQUFJLENBQUM7SUFUeEQ7OztPQUdHO0lBQ0ksTUFBTSxDQUFDLEVBQUUsQ0FBQyxPQUFlLElBQUksT0FBTyxJQUFJLGVBQWUsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUM7O0FBNUQ1RSwwQ0FrRUM7OztBQWpFQzs7R0FFRztBQUNvQix1QkFBTyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUM7QUFFOUQ7O0dBRUc7QUFDb0IsdUJBQU8sR0FBRyxlQUFlLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBRTlEOztHQUVHO0FBQ29CLHVCQUFPLEdBQUcsZUFBZSxDQUFDLEVBQUUsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUU5RDs7R0FFRztBQUNvQix1QkFBTyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUM7QUFFOUQ7O0dBRUc7QUFDb0IsdUJBQU8sR0FBRyxlQUFlLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBRTlE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QU0sQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLENBQUM7QUFDdkQsQ0FBQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCAqIGFzIGNkayBmcm9tICdhd3MtY2RrLWxpYic7XG5pbXBvcnQge1xuICBhd3NfY2VydGlmaWNhdGVtYW5hZ2VyIGFzIGNlcnRtZ3IsXG4gIGF3c19lYzIgYXMgZWMyLCBhd3NfZWNzIGFzIGVjcywgYXdzX2VsYXN0aWNsb2FkYmFsYW5jaW5ndjIgYXMgZWxidjIsXG4gIC8vIGF3c19lbGFzdGljbG9hZGJhbGFuY2luZ3YyX3RhcmdldHMgYXMgZWxiVGFyZ2V0cyxcbiAgYXdzX2lhbSBhcyBpYW0sXG4gIGF3c19sb2dzIGFzIGxvZ3MsXG4gIGF3c19yZHMgYXMgcmRzLFxuICBhd3NfczMgYXMgczMsXG4gIGF3c19zZWNyZXRzbWFuYWdlciBhcyBzZWNyZXRzbWFuYWdlcixcbn0gZnJvbSAnYXdzLWNkay1saWInO1xuaW1wb3J0IHsgQ29uc3RydWN0IH0gZnJvbSAnY29uc3RydWN0cyc7XG5cbi8vIHJlZ2lvbmFsIGF2YWlsaWJpbGl0eSBmb3IgYXVyb3JhIHNlcnZlcmxlc3Ncbi8vIHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vQW1hem9uUkRTL2xhdGVzdC9BdXJvcmFVc2VyR3VpZGUvQ29uY2VwdHMuQXVyb3JhRmVhdHVyZXNSZWdpb25zREJFbmdpbmVzLmdyaWRzLmh0bWxcbmNvbnN0IEFVUk9SQV9TRVJWRVJMRVNTX1NVUFBPUlRFRF9SRUdJT05TID0gW1xuICAndXMtZWFzdC0xJyxcbiAgJ3VzLWVhc3QtMicsXG4gICd1cy13ZXN0LTEnLFxuICAndXMtd2VzdC0yJyxcbiAgJ2FwLXNvdXRoLTEnLFxuICAnYXAtbm9ydGhlYXN0LTEnLFxuICAnYXAtbm9ydGhlYXN0LTInLFxuICAnYXAtc291dGhlYXN0LTEnLFxuICAnYXAtc291dGhlYXN0LTInLFxuICAnY2EtY2VudHJhbC0xJyxcbiAgJ2V1LWNlbnRyYWwtMScsXG4gICdldS13ZXN0LTEnLFxuICAnZXUtd2VzdC0yJyxcbiAgJ2V1LXdlc3QtMycsXG4gICdjbi1ub3J0aHdlc3QtMScsXG5dO1xuXG4vKipcbiAqIEtleWNsb2FrICB2ZXJzaW9uXG4gKi9cbmV4cG9ydCBjbGFzcyBLZXljbG9ha1ZlcnNpb24ge1xuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxMi4wLjRcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjEyXzBfNCA9IEtleWNsb2FrVmVyc2lvbi5vZignMTIuMC40Jyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTUuMC4wXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxNV8wXzAgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE1LjAuMCcpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE1LjAuMVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTVfMF8xID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxNS4wLjEnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxNS4wLjJcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE1XzBfMiA9IEtleWNsb2FrVmVyc2lvbi5vZignMTUuMC4yJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTYuMS4xXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxNl8xXzEgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE2LjEuMScpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE3LjAuMVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTdfMF8xID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxNy4wLjEnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxOC4wLjJcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE4XzBfMyA9IEtleWNsb2FrVmVyc2lvbi5vZignMTguMC4yJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTkuMC4zXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxOV8wXzMgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE5LjAuMycpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDIwLjAuNVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMjBfMF8zID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcyMC4wLjUnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAyMS4wLjBcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjIxXzBfMCA9IEtleWNsb2FrVmVyc2lvbi5vZignMjEuMC4wJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMjEuMC4xXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYyMV8wXzEgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzIxLjAuMScpO1xuXG4gIC8qKlxuICAgKiBDdXN0b20gY2x1c3RlciB2ZXJzaW9uXG4gICAqIEBwYXJhbSB2ZXJzaW9uIGN1c3RvbSB2ZXJzaW9uIG51bWJlclxuICAgKi9cbiAgcHVibGljIHN0YXRpYyBvZih2ZXJzaW9uOiBzdHJpbmcpIHsgcmV0dXJuIG5ldyBLZXljbG9ha1ZlcnNpb24odmVyc2lvbik7IH1cbiAgLyoqXG4gICAqXG4gICAqIEBwYXJhbSB2ZXJzaW9uIGNsdXN0ZXIgdmVyc2lvbiBudW1iZXJcbiAgICovXG4gIHByaXZhdGUgY29uc3RydWN0b3IocHVibGljIHJlYWRvbmx5IHZlcnNpb246IHN0cmluZykgeyB9XG59XG5cbmludGVyZmFjZSBkb2NrZXJJbWFnZU1hcCB7XG4gICdhd3MnOiBzdHJpbmc7XG4gICdhd3MtY24nOiBzdHJpbmc7XG59XG5cbmNvbnN0IEtFWUNMT0FLX0RPQ0tFUl9JTUFHRV9VUklfTUFQOiBkb2NrZXJJbWFnZU1hcCA9IHtcbiAgJ2F3cyc6ICdxdWF5LmlvL2tleWNsb2FrL2tleWNsb2FrOicsXG4gICdhd3MtY24nOiAnMDQ4OTEyMDYwOTEwLmRrci5lY3IuY24tbm9ydGh3ZXN0LTEuYW1hem9uYXdzLmNvbS5jbi9kb2NrZXJodWIvamJvc3Mva2V5Y2xvYWs6Jyxcbn07XG5cbi8qKlxuICogVGhlIEVDUyB0YXNrIGF1dG9zY2FsaW5nIGRlZmluaXRpb25cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBBdXRvU2NhbGVUYXNrIHtcbiAgLyoqXG4gICAqIFRoZSBtaW5pbWFsIGNvdW50IG9mIHRoZSB0YXNrIG51bWJlclxuICAgKlxuICAgKiBAZGVmYXVsdCAtIG5vZGVDb3VudFxuICAgKi9cbiAgcmVhZG9ubHkgbWluPzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIG1heGltYWwgY291bnQgb2YgdGhlIHRhc2sgbnVtYmVyXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gbWluICsgNVxuICAgKi9cbiAgcmVhZG9ubHkgbWF4PzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIHRhcmdldCBjcHUgdXRpbGl6YXRpb24gZm9yIHRoZSBzZXJ2aWNlIGF1dG9zY2FsaW5nXG4gICAqXG4gICAqIEBkZWZhdWx0IDc1XG4gICAqL1xuICByZWFkb25seSB0YXJnZXRDcHVVdGlsaXphdGlvbj86IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBLZXlDbG9ha1Byb3BzIHtcbiAgLyoqXG4gICAqIFRoZSBLZXljbG9hayB2ZXJzaW9uIGZvciB0aGUgY2x1c3Rlci5cbiAgICovXG4gIHJlYWRvbmx5IGtleWNsb2FrVmVyc2lvbjogS2V5Y2xvYWtWZXJzaW9uO1xuICAvKipcbiAgICogVGhlIGVudmlyb25tZW50IHZhcmlhYmxlcyB0byBwYXNzIHRvIHRoZSBrZXljbG9hayBjb250YWluZXJcbiAgICovXG4gIHJlYWRvbmx5IGVudj86IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIH07XG4gIC8qKlxuICAgKiBWUEMgZm9yIHRoZSB3b3JrbG9hZFxuICAgKi9cbiAgcmVhZG9ubHkgdnBjPzogZWMyLklWcGM7XG4gIC8qKlxuICAgKiBBQ00gY2VydGlmaWNhdGUgQVJOIHRvIGltcG9ydFxuICAgKi9cbiAgcmVhZG9ubHkgY2VydGlmaWNhdGVBcm46IHN0cmluZztcbiAgLyoqXG4gICAqIENyZWF0ZSBhIGJhc3Rpb24gaG9zdCBmb3IgZGVidWdnaW5nIG9yIHRyb3VibGUtc2hvb3RpbmdcbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGJhc3Rpb24/OiBib29sZWFuO1xuICAvKipcbiAgICogTnVtYmVyIG9mIGtleWNsb2FrIG5vZGUgaW4gdGhlIGNsdXN0ZXJcbiAgICpcbiAgICogQGRlZmF1bHQgMlxuICAgKi9cbiAgcmVhZG9ubHkgbm9kZUNvdW50PzogbnVtYmVyO1xuICAvKipcbiAgICogVlBDIHB1YmxpYyBzdWJuZXRzIGZvciBBTEJcbiAgICpcbiAgICogQGRlZmF1bHQgLSBWUEMgcHVibGljIHN1Ym5ldHNcbiAgICovXG4gIHJlYWRvbmx5IHB1YmxpY1N1Ym5ldHM/OiBlYzIuU3VibmV0U2VsZWN0aW9uO1xuICAvKipcbiAgICogVlBDIHByaXZhdGUgc3VibmV0cyBmb3Iga2V5Y2xvYWsgc2VydmljZVxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFZQQyBwcml2YXRlIHN1Ym5ldHNcbiAgICovXG4gIHJlYWRvbmx5IHByaXZhdGVTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFZQQyBzdWJuZXRzIGZvciBkYXRhYmFzZVxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFZQQyBpc29sYXRlZCBzdWJuZXRzXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZVN1Ym5ldHM/OiBlYzIuU3VibmV0U2VsZWN0aW9uO1xuICAvKipcbiAgICogRGF0YWJhc2UgaW5zdGFuY2UgdHlwZVxuICAgKlxuICAgKiBAZGVmYXVsdCByNS5sYXJnZVxuICAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2VJbnN0YW5jZVR5cGU/OiBlYzIuSW5zdGFuY2VUeXBlO1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGluc3RhbmNlIGVuZ2luZVxuICAgKlxuICAgKiBAZGVmYXVsdCAtIE15U1FMIDguMC4yMVxuICAgKi9cbiAgcmVhZG9ubHkgaW5zdGFuY2VFbmdpbmU/OiByZHMuSUluc3RhbmNlRW5naW5lO1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGNsdXN0ZXIgZW5naW5lXG4gICAqXG4gICAqIEBkZWZhdWx0IHJkcy5BdXJvcmFNeXNxbEVuZ2luZVZlcnNpb24uVkVSXzJfMDlfMVxuICAgKi9cbiAgcmVhZG9ubHkgY2x1c3RlckVuZ2luZT86IHJkcy5JQ2x1c3RlckVuZ2luZTtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gdXNlIGF1cm9yYSBzZXJ2ZXJsZXNzLiBXaGVuIGVuYWJsZWQsIHRoZSBgZGF0YWJhc2VJbnN0YW5jZVR5cGVgIGFuZFxuICAgKiBgZW5naW5lYCB3aWxsIGJlIGlnbm9yZWQuIFRoZSBgcmRzLkRhdGFiYXNlQ2x1c3RlckVuZ2luZS5BVVJPUkFfTVlTUUxgIHdpbGwgYmUgdXNlZCBhc1xuICAgKiB0aGUgZGVmYXVsdCBjbHVzdGVyIGVuZ2luZSBpbnN0ZWFkLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYXVyb3JhU2VydmVybGVzcz86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHVzZSBhdXJvcmEgc2VydmVybGVzcyB2Mi4gV2hlbiBlbmFibGVkLCB0aGUgYGRhdGFiYXNlSW5zdGFuY2VUeXBlYCB3aWxsIGJlIGlnbm9yZWQuXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBhdXJvcmFTZXJ2ZXJsZXNzVjI/OiBib29sZWFuO1xuICAvKipcbiAgICogV2hldGhlciB0byB1c2Ugc2luZ2xlIFJEUyBpbnN0YW5jZSByYXRoZXIgdGhhbiBSRFMgY2x1c3Rlci4gTm90IHJlY29tbWVuZGVkIGZvciBwcm9kdWN0aW9uLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgc2luZ2xlRGJJbnN0YW5jZT86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBkYXRhYmFzZSBiYWNrdXAgcmV0ZW5zaW9uXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gNyBkYXlzXG4gICAqL1xuICByZWFkb25seSBiYWNrdXBSZXRlbnRpb24/OiBjZGsuRHVyYXRpb247XG4gIC8qKlxuICAgKiBUaGUgc3RpY2t5IHNlc3Npb24gZHVyYXRpb24gZm9yIHRoZSBrZXljbG9hayB3b3JrbG9hZCB3aXRoIEFMQi5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBvbmUgZGF5XG4gICAqL1xuICByZWFkb25seSBzdGlja2luZXNzQ29va2llRHVyYXRpb24/OiBjZGsuRHVyYXRpb247XG4gIC8qKlxuICAgKiBBdXRvc2NhbGluZyBmb3IgdGhlIEVDUyBTZXJ2aWNlXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gbm8gZWNzIHNlcnZpY2UgYXV0b3NjYWxpbmdcbiAgICovXG4gIHJlYWRvbmx5IGF1dG9TY2FsZVRhc2s/OiBBdXRvU2NhbGVUYXNrO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHB1dCB0aGUgbG9hZCBiYWxhbmNlciBpbiB0aGUgcHVibGljIG9yIHByaXZhdGUgc3VibmV0c1xuICAgKlxuICAgKiBAZGVmYXVsdCB0cnVlXG4gICAqL1xuICByZWFkb25seSBpbnRlcm5ldEZhY2luZz86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSBob3N0bmFtZSB0byB1c2UgZm9yIHRoZSBrZXljbG9hayBzZXJ2ZXJcbiAgICovXG4gIHJlYWRvbmx5IGhvc3RuYW1lPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgbWluaW11bSBudW1iZXIgb2YgQXVyb3JhIFNlcnZlcmxlc3MgVjIgY2FwYWNpdHkgdW5pdHMuXG4gICAqXG4gICAqIEBkZWZhdWx0IDAuNVxuICAqL1xuICByZWFkb25seSBkYXRhYmFzZU1pbkNhcGFjaXR5PzogbnVtYmVyO1xuXG4gIC8qKlxuICAqIFRoZSBtYXhpbXVtIG51bWJlciBvZiBBdXJvcmEgU2VydmVybGVzcyBWMiBjYXBhY2l0eSB1bml0cy5cbiAgKlxuICAgKiBAZGVmYXVsdCAxMFxuICAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2VNYXhDYXBhY2l0eT86IG51bWJlcjtcblxuICAvKipcbiAgICogQ29udHJvbHMgd2hhdCBoYXBwZW5zIHRvIHRoZSBkYXRhYmFzZSBpZiBpdCBzdG9wcyBiZWluZyBtYW5hZ2VkIGJ5IENsb3VkRm9ybWF0aW9uXG4gICAqXG4gICAqIEBkZWZhdWx0IFJlbW92YWxQb2xpY3kuUkVUQUlOXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZVJlbW92YWxQb2xpY3k/OiBjZGsuUmVtb3ZhbFBvbGljeTtcblxuXG4gIC8qKlxuICAgKiBPdmVycmlkZXMgdGhlIGRlZmF1bHQgaW1hZ2VcbiAgICpcbiAgICogQGRlZmF1bHQgcXVheS5pby9rZXljbG9hay9rZXljbG9hazoke0tFWUNMT0FLX1ZFUlNJT059XG4gICAqL1xuICByZWFkb25seSBjb250YWluZXJJbWFnZT86IGVjcy5Db250YWluZXJJbWFnZTtcbn1cblxuZXhwb3J0IGNsYXNzIEtleUNsb2FrIGV4dGVuZHMgQ29uc3RydWN0IHtcbiAgcmVhZG9ubHkgdnBjOiBlYzIuSVZwYztcbiAgcmVhZG9ubHkgZGI/OiBEYXRhYmFzZTtcbiAgcmVhZG9ubHkgYXBwbGljYXRpb25Mb2FkQmFsYW5jZXI6IGVsYnYyLkFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyO1xuICAvLyByZWFkb25seSBuZXR3b3JrTG9hZEJhbGFuY2VyOiBlbGJ2Mi5OZXR3b3JrTG9hZEJhbGFuY2VyO1xuICByZWFkb25seSBrZXljbG9ha1NlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgY29uc3RydWN0b3Ioc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgcHJvcHM6IEtleUNsb2FrUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQpO1xuXG4gICAgY29uc3QgcmVnaW9uID0gY2RrLlN0YWNrLm9mKHRoaXMpLnJlZ2lvbjtcbiAgICBjb25zdCByZWdpb25Jc1Jlc29sdmVkID0gIWNkay5Ub2tlbi5pc1VucmVzb2x2ZWQocmVnaW9uKTtcblxuICAgIGlmIChwcm9wcy5hdXJvcmFTZXJ2ZXJsZXNzICYmIHJlZ2lvbklzUmVzb2x2ZWQgJiYgIUFVUk9SQV9TRVJWRVJMRVNTX1NVUFBPUlRFRF9SRUdJT05TLmluY2x1ZGVzKHJlZ2lvbikpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgQXVyb3JhIHNlcnZlcmxlc3MgaXMgbm90IHN1cHBvcnRlZCBpbiAke3JlZ2lvbn1gKTtcbiAgICB9XG5cbiAgICB0aGlzLmtleWNsb2FrU2VjcmV0ID0gdGhpcy5fZ2VuZXJhdGVLZXljbG9ha1NlY3JldCgpO1xuICAgIHRoaXMudnBjID0gcHJvcHMudnBjID8/IGdldE9yQ3JlYXRlVnBjKHRoaXMpO1xuXG4gICAgdGhpcy5kYiA9IHRoaXMuYWRkRGF0YWJhc2Uoe1xuICAgICAgdnBjOiB0aGlzLnZwYyxcbiAgICAgIGRhdGFiYXNlU3VibmV0czogcHJvcHMuZGF0YWJhc2VTdWJuZXRzLFxuICAgICAgaW5zdGFuY2VUeXBlOiBwcm9wcy5kYXRhYmFzZUluc3RhbmNlVHlwZSxcbiAgICAgIGluc3RhbmNlRW5naW5lOiBwcm9wcy5pbnN0YW5jZUVuZ2luZSxcbiAgICAgIGNsdXN0ZXJFbmdpbmU6IHByb3BzLmNsdXN0ZXJFbmdpbmUsXG4gICAgICBhdXJvcmFTZXJ2ZXJsZXNzOiBmYWxzZSxcbiAgICAgIGF1cm9yYVNlcnZlcmxlc3NWMjogZmFsc2UsXG4gICAgICBzaW5nbGVEYkluc3RhbmNlOiBwcm9wcy5zaW5nbGVEYkluc3RhbmNlLFxuICAgICAgYmFja3VwUmV0ZW50aW9uOiBwcm9wcy5iYWNrdXBSZXRlbnRpb24sXG4gICAgICBtYXhDYXBhY2l0eTogcHJvcHMuZGF0YWJhc2VNYXhDYXBhY2l0eSxcbiAgICAgIG1pbkNhcGFjaXR5OiBwcm9wcy5kYXRhYmFzZU1pbkNhcGFjaXR5LFxuICAgICAgcmVtb3ZhbFBvbGljeTogcHJvcHMuZGF0YWJhc2VSZW1vdmFsUG9saWN5LFxuICAgIH0pO1xuICAgIGNvbnN0IGtleWNsb2FrQ29udGFpbmVyU2VydmljZSA9IHRoaXMuYWRkS2V5Q2xvYWtDb250YWluZXJTZXJ2aWNlKHtcbiAgICAgIGRhdGFiYXNlOiB0aGlzLmRiLFxuICAgICAgdnBjOiB0aGlzLnZwYyxcbiAgICAgIGtleWNsb2FrVmVyc2lvbjogcHJvcHMua2V5Y2xvYWtWZXJzaW9uLFxuICAgICAgcHVibGljU3VibmV0czogcHJvcHMucHVibGljU3VibmV0cyxcbiAgICAgIHByaXZhdGVTdWJuZXRzOiBwcm9wcy5wcml2YXRlU3VibmV0cyxcbiAgICAgIGtleWNsb2FrU2VjcmV0OiB0aGlzLmtleWNsb2FrU2VjcmV0LFxuICAgICAgY2VydGlmaWNhdGU6IGNlcnRtZ3IuQ2VydGlmaWNhdGUuZnJvbUNlcnRpZmljYXRlQXJuKHRoaXMsICdBQ01DZXJ0JywgcHJvcHMuY2VydGlmaWNhdGVBcm4pLFxuICAgICAgYmFzdGlvbjogcHJvcHMuYmFzdGlvbixcbiAgICAgIG5vZGVDb3VudDogcHJvcHMubm9kZUNvdW50LFxuICAgICAgc3RpY2tpbmVzc0Nvb2tpZUR1cmF0aW9uOiBwcm9wcy5zdGlja2luZXNzQ29va2llRHVyYXRpb24sXG4gICAgICBhdXRvU2NhbGVUYXNrOiBwcm9wcy5hdXRvU2NhbGVUYXNrLFxuICAgICAgZW52OiBwcm9wcy5lbnYsXG4gICAgICBpbnRlcm5ldEZhY2luZzogcHJvcHMuaW50ZXJuZXRGYWNpbmcgPz8gdHJ1ZSxcbiAgICAgIGhvc3RuYW1lOiBwcm9wcy5ob3N0bmFtZSxcbiAgICAgIGNvbnRhaW5lckltYWdlOiBwcm9wcy5jb250YWluZXJJbWFnZSxcbiAgICB9KTtcblxuICAgIHRoaXMuYXBwbGljYXRpb25Mb2FkQmFsYW5jZXIgPSBrZXljbG9ha0NvbnRhaW5lclNlcnZpY2UuYXBwbGljYXRpb25Mb2FkQmFsYW5jZXI7XG4gICAgLy8gdGhpcy5uZXR3b3JrTG9hZEJhbGFuY2VyID0ga2V5Y2xvYWtDb250YWluZXJTZXJ2aWNlLm5ldHdvcmtMb2FkQmFsYW5jZXI7XG4gICAgaWYgKCFjZGsuU3RhY2sub2YodGhpcykudGVtcGxhdGVPcHRpb25zLmRlc2NyaXB0aW9uKSB7XG4gICAgICBjZGsuU3RhY2sub2YodGhpcykudGVtcGxhdGVPcHRpb25zLmRlc2NyaXB0aW9uID0gJyhTTzgwMjEpIC0gRGVwbG95IGtleWNsb2FrIG9uIEFXUyB3aXRoIGNkay1rZXljbG9hayBjb25zdHJ1Y3QgbGlicmFyeSc7XG4gICAgfVxuICB9XG4gIHB1YmxpYyBhZGREYXRhYmFzZShwcm9wczogRGF0YWJhc2VQcm9wcyk6IERhdGFiYXNlIHtcbiAgICByZXR1cm4gbmV3IERhdGFiYXNlKHRoaXMsICdEYXRhYmFzZScsIHByb3BzKTtcbiAgfVxuICBwdWJsaWMgYWRkS2V5Q2xvYWtDb250YWluZXJTZXJ2aWNlKHByb3BzOiBDb250YWluZXJTZXJ2aWNlUHJvcHMpIHtcbiAgICByZXR1cm4gbmV3IENvbnRhaW5lclNlcnZpY2UodGhpcywgJ0tleUNsb2FrQ29udGFpbmVyU2VyaXZjZScsIHByb3BzKTtcbiAgfVxuICBwcml2YXRlIF9nZW5lcmF0ZUtleWNsb2FrU2VjcmV0KCk6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQge1xuICAgIHJldHVybiBuZXcgc2VjcmV0c21hbmFnZXIuU2VjcmV0KHRoaXMsICdLQ1NlY3JldCcsIHtcbiAgICAgIGdlbmVyYXRlU2VjcmV0U3RyaW5nOiB7XG4gICAgICAgIGdlbmVyYXRlU3RyaW5nS2V5OiAncGFzc3dvcmQnLFxuICAgICAgICBleGNsdWRlUHVuY3R1YXRpb246IHRydWUsXG4gICAgICAgIHBhc3N3b3JkTGVuZ3RoOiAxMixcbiAgICAgICAgc2VjcmV0U3RyaW5nVGVtcGxhdGU6IEpTT04uc3RyaW5naWZ5KHsgdXNlcm5hbWU6ICdrZXljbG9haycgfSksXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGF0YWJhc2VQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgVlBDIGZvciB0aGUgZGF0YWJhc2VcbiAgICovXG4gIHJlYWRvbmx5IHZwYzogZWMyLklWcGM7XG4gIC8qKlxuICAgKiBWUEMgc3VibmV0cyBmb3IgZGF0YWJhc2VcbiAgICovXG4gIHJlYWRvbmx5IGRhdGFiYXNlU3VibmV0cz86IGVjMi5TdWJuZXRTZWxlY3Rpb247XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2UgaW5zdGFuY2UgdHlwZVxuICAgKlxuICAgKiBAZGVmYXVsdCByNS5sYXJnZVxuICAgKi9cbiAgcmVhZG9ubHkgaW5zdGFuY2VUeXBlPzogZWMyLkluc3RhbmNlVHlwZTtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBpbnN0YW5jZSBlbmdpbmVcbiAgICpcbiAgICogQGRlZmF1bHQgLSBNeVNRTCA4LjAuMjFcbiAgICovXG4gIHJlYWRvbmx5IGluc3RhbmNlRW5naW5lPzogcmRzLklJbnN0YW5jZUVuZ2luZTtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBjbHVzdGVyIGVuZ2luZVxuICAgKlxuICAgKiBAZGVmYXVsdCByZHMuQXVyb3JhTXlzcWxFbmdpbmVWZXJzaW9uLlZFUl8yXzA5XzFcbiAgICovXG4gIHJlYWRvbmx5IGNsdXN0ZXJFbmdpbmU/OiByZHMuSUNsdXN0ZXJFbmdpbmU7XG4gIC8qKlxuICAgKiBlbmFibGUgYXVyb3JhIHNlcnZlcmxlc3NcbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGF1cm9yYVNlcnZlcmxlc3M/OiBib29sZWFuO1xuICAvKipcbiAgICogZW5hYmxlIGF1cm9yYSBzZXJ2ZXJsZXNzIHYyXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBhdXJvcmFTZXJ2ZXJsZXNzVjI/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHVzZSBzaW5nbGUgUkRTIGluc3RhbmNlIHJhdGhlciB0aGFuIFJEUyBjbHVzdGVyLiBOb3QgcmVjb21tZW5kZWQgZm9yIHByb2R1Y3Rpb24uXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBzaW5nbGVEYkluc3RhbmNlPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIGRhdGFiYXNlIGJhY2t1cCByZXRlbnNpb25cbiAgICpcbiAgICogQGRlZmF1bHQgLSA3IGRheXNcbiAgICovXG4gIHJlYWRvbmx5IGJhY2t1cFJldGVudGlvbj86IGNkay5EdXJhdGlvbjtcbiAgLyoqXG4gICAqIFRoZSBtaW5pbXVtIG51bWJlciBvZiBBdXJvcmEgU2VydmVybGVzcyBWMiBjYXBhY2l0eSB1bml0cy5cbiAgICpcbiAgICogQGRlZmF1bHQgMC41XG4gICovXG4gIHJlYWRvbmx5IG1pbkNhcGFjaXR5PzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIG1heGltdW0gbnVtYmVyIG9mIEF1cm9yYSBTZXJ2ZXJsZXNzIFYyIGNhcGFjaXR5IHVuaXRzLlxuICAgKlxuICAgKiBAZGVmYXVsdCAxMFxuICAgKi9cbiAgcmVhZG9ubHkgbWF4Q2FwYWNpdHk/OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIENvbnRyb2xzIHdoYXQgaGFwcGVucyB0byB0aGUgZGF0YWJhc2UgaWYgaXQgc3RvcHMgYmVpbmcgbWFuYWdlZCBieSBDbG91ZEZvcm1hdGlvblxuICAgKlxuICAgKiBAZGVmYXVsdCBSZW1vdmFsUG9saWN5LlJFVEFJTlxuICAgKi9cbiAgcmVhZG9ubHkgcmVtb3ZhbFBvbGljeT86IGNkay5SZW1vdmFsUG9saWN5O1xufVxuXG4vKipcbiAqIERhdGFiYXNlIGNvbmZpZ3VyYXRpb25cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBEYXRhYmFzZUNvbmZpZyB7XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2Ugc2VjcmV0LlxuICAgKi9cbiAgcmVhZG9ubHkgc2VjcmV0OiBzZWNyZXRzbWFuYWdlci5JU2VjcmV0O1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGNvbm5uZWN0aW9ucy5cbiAgICovXG4gIHJlYWRvbmx5IGNvbm5lY3Rpb25zOiBlYzIuQ29ubmVjdGlvbnM7XG4gIC8qKlxuICAgKiBUaGUgZW5kcG9pbnQgYWRkcmVzcyBmb3IgdGhlIGRhdGFiYXNlLlxuICAgKi9cbiAgcmVhZG9ubHkgZW5kcG9pbnQ6IHN0cmluZztcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzYWUgaWRlbnRpZmllci5cbiAgICovXG4gIHJlYWRvbmx5IGlkZW50aWZpZXI6IHN0cmluZztcbn1cblxuLyoqXG4gKiBSZXByZXNlbnRzIHRoZSBkYXRhYmFzZSBpbnN0YW5jZSBvciBkYXRhYmFzZSBjbHVzdGVyXG4gKi9cbmV4cG9ydCBjbGFzcyBEYXRhYmFzZSBleHRlbmRzIENvbnN0cnVjdCB7XG4gIHJlYWRvbmx5IHZwYzogZWMyLklWcGM7XG4gIHJlYWRvbmx5IGNsdXN0ZXJFbmRwb2ludEhvc3RuYW1lOiBzdHJpbmc7XG4gIHJlYWRvbmx5IGNsdXN0ZXJJZGVudGlmaWVyOiBzdHJpbmc7XG4gIHJlYWRvbmx5IHNlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgcmVhZG9ubHkgY29ubmVjdGlvbnM6IGVjMi5Db25uZWN0aW9ucztcbiAgcHJpdmF0ZSByZWFkb25seSBfbXlzcWxMaXN0ZW5lclBvcnQ6IG51bWJlciA9IDMzMDY7XG5cbiAgY29uc3RydWN0b3Ioc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgcHJvcHM6IERhdGFiYXNlUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQpO1xuICAgIHRoaXMudnBjID0gcHJvcHMudnBjO1xuICAgIGxldCBjb25maWc7XG4gICAgaWYgKHByb3BzLmF1cm9yYVNlcnZlcmxlc3MpIHtcbiAgICAgIGNvbmZpZyA9IHRoaXMuX2NyZWF0ZVNlcnZlcmxlc3NDbHVzdGVyKHByb3BzKTtcbiAgICB9IGVsc2UgaWYgKHByb3BzLmF1cm9yYVNlcnZlcmxlc3NWMikge1xuICAgICAgY29uZmlnID0gdGhpcy5fY3JlYXRlU2VydmVybGVzc1YyQ2x1c3Rlcihwcm9wcyk7XG4gICAgfSBlbHNlIGlmIChwcm9wcy5zaW5nbGVEYkluc3RhbmNlKSB7XG4gICAgICBjb25maWcgPSB0aGlzLl9jcmVhdGVSZHNJbnN0YW5jZShwcm9wcyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbmZpZyA9IHRoaXMuX2NyZWF0ZVJkc0NsdXN0ZXIocHJvcHMpO1xuICAgIH1cbiAgICB0aGlzLnNlY3JldCA9IGNvbmZpZy5zZWNyZXQ7XG4gICAgLy8gYWxsb3cgaW50ZXJuYWxseSBmcm9tIHRoZSBzYW1lIHNlY3VyaXR5IGdyb3VwXG4gICAgY29uZmlnLmNvbm5lY3Rpb25zLmFsbG93SW50ZXJuYWxseShlYzIuUG9ydC50Y3AodGhpcy5fbXlzcWxMaXN0ZW5lclBvcnQpKTtcbiAgICAvLyBhbGxvdyBmcm9tIHRoZSB3aG9sZSB2cGMgY2lkclxuICAgIGNvbmZpZy5jb25uZWN0aW9ucy5hbGxvd0Zyb20oZWMyLlBlZXIuaXB2NChwcm9wcy52cGMudnBjQ2lkckJsb2NrKSwgZWMyLlBvcnQudGNwKHRoaXMuX215c3FsTGlzdGVuZXJQb3J0KSk7XG4gICAgdGhpcy5jbHVzdGVyRW5kcG9pbnRIb3N0bmFtZSA9IGNvbmZpZy5lbmRwb2ludDtcbiAgICB0aGlzLmNsdXN0ZXJJZGVudGlmaWVyID0gY29uZmlnLmlkZW50aWZpZXI7XG4gICAgdGhpcy5jb25uZWN0aW9ucyA9IGNvbmZpZy5jb25uZWN0aW9ucztcbiAgICBwcmludE91dHB1dCh0aGlzLCAnREJTZWNyZXRBcm4nLCBjb25maWcuc2VjcmV0LnNlY3JldEFybik7XG4gICAgcHJpbnRPdXRwdXQodGhpcywgJ2NsdXN0ZXJFbmRwb2ludEhvc3RuYW1lJywgdGhpcy5jbHVzdGVyRW5kcG9pbnRIb3N0bmFtZSk7XG4gICAgcHJpbnRPdXRwdXQodGhpcywgJ2NsdXN0ZXJJZGVudGlmaWVyJywgdGhpcy5jbHVzdGVySWRlbnRpZmllcik7XG4gIH1cbiAgcHJpdmF0ZSBfY3JlYXRlUmRzSW5zdGFuY2UocHJvcHM6IERhdGFiYXNlUHJvcHMpOiBEYXRhYmFzZUNvbmZpZyB7XG4gICAgY29uc3QgZGJJbnN0YW5jZSA9IG5ldyByZHMuRGF0YWJhc2VJbnN0YW5jZSh0aGlzLCAnREJJbnN0YW5jZScsIHtcbiAgICAgIHZwYzogcHJvcHMudnBjLFxuICAgICAgZGF0YWJhc2VOYW1lOiAna2V5Y2xvYWsnLFxuICAgICAgdnBjU3VibmV0czogcHJvcHMuZGF0YWJhc2VTdWJuZXRzLFxuICAgICAgZW5naW5lOiBwcm9wcy5pbnN0YW5jZUVuZ2luZSA/PyByZHMuRGF0YWJhc2VJbnN0YW5jZUVuZ2luZS5teXNxbCh7XG4gICAgICAgIHZlcnNpb246IHJkcy5NeXNxbEVuZ2luZVZlcnNpb24uVkVSXzhfMF8yMSxcbiAgICAgIH0pLFxuICAgICAgc3RvcmFnZUVuY3J5cHRlZDogdHJ1ZSxcbiAgICAgIGJhY2t1cFJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uID8/IGNkay5EdXJhdGlvbi5kYXlzKDcpLFxuICAgICAgY3JlZGVudGlhbHM6IHJkcy5DcmVkZW50aWFscy5mcm9tR2VuZXJhdGVkU2VjcmV0KCdhZG1pbicpLFxuICAgICAgaW5zdGFuY2VUeXBlOiBwcm9wcy5pbnN0YW5jZVR5cGUgPz8gbmV3IGVjMi5JbnN0YW5jZVR5cGUoJ3I1LmxhcmdlJyksXG4gICAgICBwYXJhbWV0ZXJHcm91cDogcmRzLlBhcmFtZXRlckdyb3VwLmZyb21QYXJhbWV0ZXJHcm91cE5hbWUodGhpcywgJ1BhcmFtZXRlckdyb3VwJywgJ2RlZmF1bHQubXlzcWw4LjAnKSxcbiAgICAgIGRlbGV0aW9uUHJvdGVjdGlvbjogZmFsc2UsXG4gICAgICByZW1vdmFsUG9saWN5OiBwcm9wcy5yZW1vdmFsUG9saWN5ID8/IGNkay5SZW1vdmFsUG9saWN5LlJFVEFJTixcbiAgICB9KTtcbiAgICByZXR1cm4ge1xuICAgICAgY29ubmVjdGlvbnM6IGRiSW5zdGFuY2UuY29ubmVjdGlvbnMsXG4gICAgICBlbmRwb2ludDogZGJJbnN0YW5jZS5kYkluc3RhbmNlRW5kcG9pbnRBZGRyZXNzLFxuICAgICAgaWRlbnRpZmllcjogZGJJbnN0YW5jZS5pbnN0YW5jZUlkZW50aWZpZXIsXG4gICAgICBzZWNyZXQ6IGRiSW5zdGFuY2Uuc2VjcmV0ISxcbiAgICB9O1xuICB9XG4gIC8vIGNyZWF0ZSBhIFJEUyBmb3IgTXlTUUwgREIgY2x1c3RlclxuICBwcml2YXRlIF9jcmVhdGVSZHNDbHVzdGVyKHByb3BzOiBEYXRhYmFzZVByb3BzKTogRGF0YWJhc2VDb25maWcge1xuICAgIGNvbnN0IGRiQ2x1c3RlciA9IG5ldyByZHMuRGF0YWJhc2VDbHVzdGVyKHRoaXMsICdEQkNsdXN0ZXInLCB7XG4gICAgICBlbmdpbmU6IHByb3BzLmNsdXN0ZXJFbmdpbmUgPz8gcmRzLkRhdGFiYXNlQ2x1c3RlckVuZ2luZS5hdXJvcmFNeXNxbCh7XG4gICAgICAgIHZlcnNpb246IHJkcy5BdXJvcmFNeXNxbEVuZ2luZVZlcnNpb24uVkVSXzJfMDlfMSxcbiAgICAgIH0pLFxuICAgICAgZGVmYXVsdERhdGFiYXNlTmFtZTogJ2tleWNsb2FrJyxcbiAgICAgIGRlbGV0aW9uUHJvdGVjdGlvbjogZmFsc2UsXG4gICAgICBjcmVkZW50aWFsczogcmRzLkNyZWRlbnRpYWxzLmZyb21HZW5lcmF0ZWRTZWNyZXQoJ2FkbWluJyksXG4gICAgICBpbnN0YW5jZVByb3BzOiB7XG4gICAgICAgIHZwYzogcHJvcHMudnBjLFxuICAgICAgICB2cGNTdWJuZXRzOiBwcm9wcy5kYXRhYmFzZVN1Ym5ldHMsXG4gICAgICAgIGluc3RhbmNlVHlwZTogcHJvcHMuaW5zdGFuY2VUeXBlID8/IG5ldyBlYzIuSW5zdGFuY2VUeXBlKCdyNS5sYXJnZScpLFxuICAgICAgfSxcbiAgICAgIHBhcmFtZXRlckdyb3VwOiByZHMuUGFyYW1ldGVyR3JvdXAuZnJvbVBhcmFtZXRlckdyb3VwTmFtZSh0aGlzLCAnUGFyYW1ldGVyR3JvdXAnLCAnZGVmYXVsdC5hdXJvcmEtbXlzcWw4LjAnKSxcbiAgICAgIGJhY2t1cDoge1xuICAgICAgICByZXRlbnRpb246IHByb3BzLmJhY2t1cFJldGVudGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cyg3KSxcbiAgICAgIH0sXG4gICAgICBzdG9yYWdlRW5jcnlwdGVkOiB0cnVlLFxuICAgICAgcmVtb3ZhbFBvbGljeTogcHJvcHMucmVtb3ZhbFBvbGljeSA/PyBjZGsuUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgfSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGNvbm5lY3Rpb25zOiBkYkNsdXN0ZXIuY29ubmVjdGlvbnMsXG4gICAgICBlbmRwb2ludDogZGJDbHVzdGVyLmNsdXN0ZXJFbmRwb2ludC5ob3N0bmFtZSxcbiAgICAgIGlkZW50aWZpZXI6IGRiQ2x1c3Rlci5jbHVzdGVySWRlbnRpZmllcixcbiAgICAgIHNlY3JldDogZGJDbHVzdGVyLnNlY3JldCEsXG4gICAgfTtcbiAgfVxuICBwcml2YXRlIF9jcmVhdGVTZXJ2ZXJsZXNzQ2x1c3Rlcihwcm9wczogRGF0YWJhc2VQcm9wcyk6IERhdGFiYXNlQ29uZmlnIHtcbiAgICBjb25zdCBkYkNsdXN0ZXIgPSBuZXcgcmRzLlNlcnZlcmxlc3NDbHVzdGVyKHRoaXMsICdBdXJvcmFTZXJ2ZXJsZXNzQ2x1c3RlcicsIHtcbiAgICAgIGVuZ2luZTogcmRzLkRhdGFiYXNlQ2x1c3RlckVuZ2luZS5BVVJPUkFfTVlTUUwsXG4gICAgICB2cGM6IHByb3BzLnZwYyxcbiAgICAgIGRlZmF1bHREYXRhYmFzZU5hbWU6ICdrZXljbG9haycsXG4gICAgICB2cGNTdWJuZXRzOiBwcm9wcy5kYXRhYmFzZVN1Ym5ldHMsXG4gICAgICBjcmVkZW50aWFsczogcmRzLkNyZWRlbnRpYWxzLmZyb21HZW5lcmF0ZWRTZWNyZXQoJ2FkbWluJyksXG4gICAgICBiYWNrdXBSZXRlbnRpb246IHByb3BzLmJhY2t1cFJldGVudGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cyg3KSxcbiAgICAgIGRlbGV0aW9uUHJvdGVjdGlvbjogZmFsc2UsXG4gICAgICByZW1vdmFsUG9saWN5OiBwcm9wcy5yZW1vdmFsUG9saWN5ID8/IGNkay5SZW1vdmFsUG9saWN5LlJFVEFJTixcbiAgICAgIHBhcmFtZXRlckdyb3VwOiByZHMuUGFyYW1ldGVyR3JvdXAuZnJvbVBhcmFtZXRlckdyb3VwTmFtZSh0aGlzLCAnUGFyYW1ldGVyR3JvdXAnLCAnZGVmYXVsdC5hdXJvcmEtbXlzcWw4LjAnKSxcbiAgICB9KTtcbiAgICByZXR1cm4ge1xuICAgICAgY29ubmVjdGlvbnM6IGRiQ2x1c3Rlci5jb25uZWN0aW9ucyxcbiAgICAgIGVuZHBvaW50OiBkYkNsdXN0ZXIuY2x1c3RlckVuZHBvaW50Lmhvc3RuYW1lLFxuICAgICAgaWRlbnRpZmllcjogZGJDbHVzdGVyLmNsdXN0ZXJJZGVudGlmaWVyLFxuICAgICAgc2VjcmV0OiBkYkNsdXN0ZXIuc2VjcmV0ISxcbiAgICB9O1xuICB9XG4gIC8vIGNyZWF0ZSBhIFJEUyBmb3IgTXlTUUwgREIgY2x1c3RlciB3aXRoIEF1cm9yYSBTZXJ2ZXJsZXNzIHYyXG4gIHByaXZhdGUgX2NyZWF0ZVNlcnZlcmxlc3NWMkNsdXN0ZXIocHJvcHM6IERhdGFiYXNlUHJvcHMpOiBEYXRhYmFzZUNvbmZpZyB7XG4gICAgY29uc3QgZGJDbHVzdGVyID0gbmV3IHJkcy5EYXRhYmFzZUNsdXN0ZXIodGhpcywgJ0RCQ2x1c3RlcicsIHtcbiAgICAgIGVuZ2luZTogcHJvcHMuY2x1c3RlckVuZ2luZSA/PyByZHMuRGF0YWJhc2VDbHVzdGVyRW5naW5lLmF1cm9yYU15c3FsKHtcbiAgICAgICAgdmVyc2lvbjogcmRzLkF1cm9yYU15c3FsRW5naW5lVmVyc2lvbi5WRVJfM18wMl8wLFxuICAgICAgfSksXG4gICAgICBkZWZhdWx0RGF0YWJhc2VOYW1lOiAna2V5Y2xvYWsnLFxuICAgICAgZGVsZXRpb25Qcm90ZWN0aW9uOiBmYWxzZSxcbiAgICAgIGNyZWRlbnRpYWxzOiByZHMuQ3JlZGVudGlhbHMuZnJvbUdlbmVyYXRlZFNlY3JldCgnYWRtaW4nKSxcbiAgICAgIGluc3RhbmNlUHJvcHM6IHtcbiAgICAgICAgdnBjOiBwcm9wcy52cGMsXG4gICAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgICAgLy8gU3BlY2lmeSBzZXJ2ZXJsZXNzIEluc3RhbmNlIFR5cGVcbiAgICAgICAgaW5zdGFuY2VUeXBlOiBuZXcgZWMyLkluc3RhbmNlVHlwZSgnc2VydmVybGVzcycpLFxuICAgICAgfSxcbiAgICAgIC8vIFNldCBkZWZhdWx0IHBhcmFtZXRlciBncm91cCBmb3IgQXVyb3JhIE15U1FMIDguMFxuICAgICAgcGFyYW1ldGVyR3JvdXA6IHJkcy5QYXJhbWV0ZXJHcm91cC5mcm9tUGFyYW1ldGVyR3JvdXBOYW1lKHRoaXMsICdQYXJhbWV0ZXJHcm91cCcsICdkZWZhdWx0LmF1cm9yYS1teXNxbDguMCcpLFxuICAgICAgYmFja3VwOiB7XG4gICAgICAgIHJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uID8/IGNkay5EdXJhdGlvbi5kYXlzKDcpLFxuICAgICAgfSxcbiAgICAgIHN0b3JhZ2VFbmNyeXB0ZWQ6IHRydWUsXG4gICAgICByZW1vdmFsUG9saWN5OiBwcm9wcy5yZW1vdmFsUG9saWN5ID8/IGNkay5SZW1vdmFsUG9saWN5LlJFVEFJTixcbiAgICB9KTtcbiAgICAvLyBTZXQgU2VydmVybGVzcyBWMiBTY2FsaW5nIENvbmZpZ3VyYXRpb25cbiAgICAvLyBUT0RPOiBVc2UgY2xlYW5lciB3YXkgdG8gc2V0IHNjYWxpbmcgY29uZmlndXJhdGlvbi5cbiAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vYXdzL2F3cy1jZGsvaXNzdWVzLzIwMTk3XG4gICAgKFxuICAgICAgZGJDbHVzdGVyLm5vZGUuZmluZENoaWxkKCdSZXNvdXJjZScpIGFzIHJkcy5DZm5EQkNsdXN0ZXJcbiAgICApLnNlcnZlcmxlc3NWMlNjYWxpbmdDb25maWd1cmF0aW9uID0ge1xuICAgICAgbWluQ2FwYWNpdHk6IHByb3BzLm1pbkNhcGFjaXR5ID8/IDAuNSxcbiAgICAgIG1heENhcGFjaXR5OiBwcm9wcy5tYXhDYXBhY2l0eSA/PyAxMCxcbiAgICB9O1xuICAgIHJldHVybiB7XG4gICAgICBjb25uZWN0aW9uczogZGJDbHVzdGVyLmNvbm5lY3Rpb25zLFxuICAgICAgZW5kcG9pbnQ6IGRiQ2x1c3Rlci5jbHVzdGVyRW5kcG9pbnQuaG9zdG5hbWUsXG4gICAgICBpZGVudGlmaWVyOiBkYkNsdXN0ZXIuY2x1c3RlcklkZW50aWZpZXIsXG4gICAgICBzZWNyZXQ6IGRiQ2x1c3Rlci5zZWNyZXQhLFxuICAgIH07XG4gIH1cbn1cblxuZXhwb3J0IGludGVyZmFjZSBDb250YWluZXJTZXJ2aWNlUHJvcHMge1xuICAvKipcbiAgICogVGhlIGVudmlyb25tZW50IHZhcmlhYmxlcyB0byBwYXNzIHRvIHRoZSBrZXljbG9hayBjb250YWluZXJcbiAgICovXG4gIHJlYWRvbmx5IGVudj86IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIH07XG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIGZvciB0aGUgY29udGFpbmVyIGltYWdlXG4gICAqL1xuICByZWFkb25seSBrZXljbG9ha1ZlcnNpb246IEtleWNsb2FrVmVyc2lvbjtcbiAgLyoqXG4gICAqIFRoZSBWUEMgZm9yIHRoZSBzZXJ2aWNlXG4gICAqL1xuICByZWFkb25seSB2cGM6IGVjMi5JVnBjO1xuICAvKipcbiAgICogVlBDIHN1Ym5ldHMgZm9yIGtleWNsb2FrIHNlcnZpY2VcbiAgICovXG4gIHJlYWRvbmx5IHByaXZhdGVTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFZQQyBwdWJsaWMgc3VibmV0cyBmb3IgQUxCXG4gICAqL1xuICByZWFkb25seSBwdWJsaWNTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFRoZSBSRFMgZGF0YWJhc2UgZm9yIHRoZSBzZXJ2aWNlXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZTogRGF0YWJhc2U7XG4gIC8qKlxuICAgKiBUaGUgc2VjcmV0cyBtYW5hZ2VyIHNlY3JldCBmb3IgdGhlIGtleWNsb2FrXG4gICAqL1xuICByZWFkb25seSBrZXljbG9ha1NlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgLyoqXG4gICAqIFRoZSBBQ00gY2VydGlmaWNhdGVcbiAgICovXG4gIHJlYWRvbmx5IGNlcnRpZmljYXRlOiBjZXJ0bWdyLklDZXJ0aWZpY2F0ZTtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gY3JlYXRlIHRoZSBiYXN0aW9uIGhvc3RcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGJhc3Rpb24/OiBib29sZWFuO1xuICAvKipcbiAgICogV2hldGhlciB0byBlbmFibGUgdGhlIEVDUyBzZXJ2aWNlIGRlcGxveW1lbnQgY2lyY3VpdCBicmVha2VyXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBjaXJjdWl0QnJlYWtlcj86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBOdW1iZXIgb2Yga2V5Y2xvYWsgbm9kZSBpbiB0aGUgY2x1c3RlclxuICAgKlxuICAgKiBAZGVmYXVsdCAxXG4gICAqL1xuICByZWFkb25seSBub2RlQ291bnQ/OiBudW1iZXI7XG4gIC8qKlxuICAgKiBUaGUgc3RpY2t5IHNlc3Npb24gZHVyYXRpb24gZm9yIHRoZSBrZXljbG9hayB3b3JrbG9hZCB3aXRoIEFMQi5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBvbmUgZGF5XG4gICAqL1xuICByZWFkb25seSBzdGlja2luZXNzQ29va2llRHVyYXRpb24/OiBjZGsuRHVyYXRpb247XG5cbiAgLyoqXG4gICAqIEF1dG9zY2FsaW5nIGZvciB0aGUgRUNTIFNlcnZpY2VcbiAgICpcbiAgICogQGRlZmF1bHQgLSBubyBlY3Mgc2VydmljZSBhdXRvc2NhbGluZ1xuICAgKi9cbiAgcmVhZG9ubHkgYXV0b1NjYWxlVGFzaz86IEF1dG9TY2FsZVRhc2s7XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gcHV0IHRoZSBwdXQgdGhlIGxvYWQgYmFsYW5jZXIgaW4gdGhlIHB1YmxpYyBvciBwcml2YXRlIHN1Ym5ldHNcbiAgICpcbiAgICogQGRlZmF1bHQgdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgaW50ZXJuZXRGYWNpbmc/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBUaGUgaG9zdG5hbWUgdG8gdXNlIGZvciB0aGUga2V5Y2xvYWsgc2VydmVyXG4gICAqL1xuICByZWFkb25seSBob3N0bmFtZT86IHN0cmluZztcblxuXG4gIC8qKlxuICAgKiBPdmVycmlkZXMgdGhlIGRlZmF1bHQgaW1hZ2VcbiAgICpcbiAgICogQGRlZmF1bHQgcXVheS5pby9rZXljbG9hay9rZXljbG9hazoke0tFWUNMT0FLX1ZFUlNJT059XG4gICAqL1xuICByZWFkb25seSBjb250YWluZXJJbWFnZT86IGVjcy5Db250YWluZXJJbWFnZTtcblxuICAvKipcbiAgICogVGhlIG51bWJlciBvZiBjcHUgdW5pdHMgdXNlZCBieSB0aGUgS2V5Y2xvYWsgdGFzay5cbiAgICogWW91IG11c3QgdXNlIG9uZSBvZiB0aGUgZm9sbG93aW5nIHZhbHVlcywgd2hpY2ggZGV0ZXJtaW5lcyB5b3VyIHJhbmdlIG9mIHZhbGlkIHZhbHVlcyBmb3IgdGhlIG1lbW9yeSBwYXJhbWV0ZXI6XG4gICAqIDI1NiAoLjI1IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IDUxMiAoMC41IEdCKSwgMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpXG4gICAqIDUxMiAoLjUgdkNQVSkgLSBBdmFpbGFibGUgbWVtb3J5IHZhbHVlczogMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpLCAzMDcyICgzIEdCKSwgNDA5NiAoNCBHQilcbiAgICogMTAyNCAoMSB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpLCA1MTIwICg1IEdCKSwgNjE0NCAoNiBHQiksIDcxNjggKDcgR0IpLCA4MTkyICg4IEdCKVxuICAgKiAyMDQ4ICgyIHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gNDA5NiAoNCBHQikgYW5kIDE2Mzg0ICgxNiBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKVxuICAgKiA0MDk2ICg0IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gODE5MiAoOCBHQikgYW5kIDMwNzIwICgzMCBHQikgaW4gaW5jcmVtZW50cyBvZiAxMDI0ICgxIEdCKVxuICAgKiA4MTkyICg4IHZDUFUpIC0gQXZhaWxhYmxlIG1lbW9yeSB2YWx1ZXM6IEJldHdlZW4gMTYzODQgKDE2IEdCKSBhbmQgNjE0NDAgKDYwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDQwOTYgKDQgR0IpXG4gICAqIDE2Mzg0ICgxNiB2Q1BVKSAtIEF2YWlsYWJsZSBtZW1vcnkgdmFsdWVzOiBCZXR3ZWVuIDMyNzY4ICgzMiBHQikgYW5kIDEyMjg4MCAoMTIwIEdCKSBpbiBpbmNyZW1lbnRzIG9mIDgxOTIgKDggR0IpXG4gICAqXG4gICAqIEBkZWZhdWx0IDIwNDhcbiAgICovXG4gIHJlYWRvbmx5IGNwdT86IG51bWJlcjtcblxuICAvKipcbiAgICogVGhlIGFtb3VudCAoaW4gTWlCKSBvZiBtZW1vcnkgdXNlZCBieSB0aGUgdGFzay5cbiAgICogWW91IG11c3QgdXNlIG9uZSBvZiB0aGUgZm9sbG93aW5nIHZhbHVlcywgd2hpY2ggZGV0ZXJtaW5lcyB5b3VyIHJhbmdlIG9mIHZhbGlkIHZhbHVlcyBmb3IgdGhlIGNwdSBwYXJhbWV0ZXI6XG4gICAqIDUxMiAoMC41IEdCKSwgMTAyNCAoMSBHQiksIDIwNDggKDIgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDI1NiAoLjI1IHZDUFUpXG4gICAqIDEwMjQgKDEgR0IpLCAyMDQ4ICgyIEdCKSwgMzA3MiAoMyBHQiksIDQwOTYgKDQgR0IpIC0gQXZhaWxhYmxlIGNwdSB2YWx1ZXM6IDUxMiAoLjUgdkNQVSlcbiAgICogMjA0OCAoMiBHQiksIDMwNzIgKDMgR0IpLCA0MDk2ICg0IEdCKSwgNTEyMCAoNSBHQiksIDYxNDQgKDYgR0IpLCA3MTY4ICg3IEdCKSwgODE5MiAoOCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMTAyNCAoMSB2Q1BVKVxuICAgKiBCZXR3ZWVuIDQwOTYgKDQgR0IpIGFuZCAxNjM4NCAoMTYgR0IpIGluIGluY3JlbWVudHMgb2YgMTAyNCAoMSBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMjA0OCAoMiB2Q1BVKVxuICAgKiBCZXR3ZWVuIDgxOTIgKDggR0IpIGFuZCAzMDcyMCAoMzAgR0IpIGluIGluY3JlbWVudHMgb2YgMTAyNCAoMSBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogNDA5NiAoNCB2Q1BVKVxuICAgKiBCZXR3ZWVuIDE2Mzg0ICgxNiBHQikgYW5kIDYxNDQwICg2MCBHQikgaW4gaW5jcmVtZW50cyBvZiA0MDk2ICg0IEdCKSAtIEF2YWlsYWJsZSBjcHUgdmFsdWVzOiA4MTkyICg4IHZDUFUpXG4gICAqIEJldHdlZW4gMzI3NjggKDMyIEdCKSBhbmQgMTIyODgwICgxMjAgR0IpIGluIGluY3JlbWVudHMgb2YgODE5MiAoOCBHQikgLSBBdmFpbGFibGUgY3B1IHZhbHVlczogMTYzODQgKDE2IHZDUFUpXG4gICAqXG4gICAqIEBkZWZhdWx0IDQwOTZcbiAgICovXG4gIHJlYWRvbmx5IG1lbW9yeUxpbWl0TWlCPzogbnVtYmVyO1xufVxuXG5leHBvcnQgY2xhc3MgQ29udGFpbmVyU2VydmljZSBleHRlbmRzIENvbnN0cnVjdCB7XG4gIHJlYWRvbmx5IHNlcnZpY2U6IGVjcy5GYXJnYXRlU2VydmljZTtcbiAgcmVhZG9ubHkgYXBwbGljYXRpb25Mb2FkQmFsYW5jZXI6IGVsYnYyLkFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyO1xuICAvLyByZWFkb25seSBuZXR3b3JrTG9hZEJhbGFuY2VyOiBlbGJ2Mi5OZXR3b3JrTG9hZEJhbGFuY2VyO1xuICByZWFkb25seSBrZXljbG9ha1VzZXJTZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBDb250YWluZXJTZXJ2aWNlUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQpO1xuXG4gICAgY29uc3Qge2NwdSA9IDIwNDgsIG1lbW9yeUxpbWl0TWlCPTQwOTZ9ID0gcHJvcHM7XG5cbiAgICBjb25zdCByZWdpb24gPSBjZGsuU3RhY2sub2YodGhpcykucmVnaW9uO1xuICAgIGNvbnN0IGNvbnRhaW5lclBvcnQgPSA4MDgwO1xuICAgIGNvbnN0IGNvbm5lY3Rpb25TdHJpbmcgPSBgamRiYzpteXNxbDovLyR7cHJvcHMuZGF0YWJhc2UuY2x1c3RlckVuZHBvaW50SG9zdG5hbWV9OjMzMDYva2V5Y2xvYWtgO1xuICAgIC8vIGNvbnN0IHByb3RvY29sID0gZWxidjIuQXBwbGljYXRpb25Qcm90b2NvbC5IVFRQO1xuICAgIGNvbnN0IGVudHJ5UG9pbnQgPSBbJy9vcHQva2V5Y2xvYWsvYmluL2tjLnNoJywgJ3N0YXJ0JywgJy0tb3B0aW1pemVkJ107XG4gICAgY29uc3QgczNQaW5nQnVja2V0ID0gbmV3IHMzLkJ1Y2tldCh0aGlzLCAna2V5Y2xvYWtfczNfcGluZycpO1xuICAgIGNvbnN0IGltYWdlID0gcHJvcHMuY29udGFpbmVySW1hZ2UgPz8gZWNzLkNvbnRhaW5lckltYWdlLmZyb21SZWdpc3RyeSh0aGlzLmdldEtleUNsb2FrRG9ja2VySW1hZ2VVcmkocHJvcHMua2V5Y2xvYWtWZXJzaW9uLnZlcnNpb24pKTtcbiAgICBjb25zdCBzZWNyZXRzOiB7W2tleTogc3RyaW5nXTogY2RrLmF3c19lY3MuU2VjcmV0fSA9IHtcbiAgICAgIEtDX0RCX1BBU1NXT1JEOiBlY3MuU2VjcmV0LmZyb21TZWNyZXRzTWFuYWdlcihwcm9wcy5kYXRhYmFzZS5zZWNyZXQsICdwYXNzd29yZCcpLFxuICAgICAgS0VZQ0xPQUtfQURNSU46IGVjcy5TZWNyZXQuZnJvbVNlY3JldHNNYW5hZ2VyKHByb3BzLmtleWNsb2FrU2VjcmV0LCAndXNlcm5hbWUnKSxcbiAgICAgIEtFWUNMT0FLX0FETUlOX1BBU1NXT1JEOiBlY3MuU2VjcmV0LmZyb21TZWNyZXRzTWFuYWdlcihwcm9wcy5rZXljbG9ha1NlY3JldCwgJ3Bhc3N3b3JkJyksXG4gICAgfTtcbiAgICBjb25zdCBwb3J0TWFwcGluZ3M6IGVjcy5Qb3J0TWFwcGluZ1tdID0gW1xuICAgICAgeyBjb250YWluZXJQb3J0OiBjb250YWluZXJQb3J0IH0sIC8vIHdlYiBwb3J0XG4gICAgICB7IGNvbnRhaW5lclBvcnQ6IDc4MDAgfSwgLy8gamdyb3Vwcy1zM1xuICAgICAgeyBjb250YWluZXJQb3J0OiA1NzgwMCB9LCAvLyBqZ3JvdXBzLXMzLWZkXG4gICAgXTtcbiAgICBjb25zdCB2cGMgPSBwcm9wcy52cGM7XG4gICAgY29uc3QgY2x1c3RlciA9IG5ldyBlY3MuQ2x1c3Rlcih0aGlzLCAnQ2x1c3RlcicsIHsgdnBjLCBjb250YWluZXJJbnNpZ2h0czogdHJ1ZSB9KTtcbiAgICBjbHVzdGVyLm5vZGUuYWRkRGVwZW5kZW5jeShwcm9wcy5kYXRhYmFzZSk7XG4gICAgY29uc3QgZXhlY3V0aW9uUm9sZSA9IG5ldyBpYW0uUm9sZSh0aGlzLCAnVGFza1JvbGUnLCB7XG4gICAgICBhc3N1bWVkQnk6IG5ldyBpYW0uQ29tcG9zaXRlUHJpbmNpcGFsKFxuICAgICAgICBuZXcgaWFtLlNlcnZpY2VQcmluY2lwYWwoJ2Vjcy5hbWF6b25hd3MuY29tJyksXG4gICAgICAgIG5ldyBpYW0uU2VydmljZVByaW5jaXBhbCgnZWNzLXRhc2tzLmFtYXpvbmF3cy5jb20nKSxcbiAgICAgICksXG4gICAgfSk7XG4gICAgY29uc3QgdGFza0RlZmluaXRpb24gPSBuZXcgZWNzLkZhcmdhdGVUYXNrRGVmaW5pdGlvbih0aGlzLCAnVGFza0RlZicsIHtcbiAgICAgIGNwdSxcbiAgICAgIG1lbW9yeUxpbWl0TWlCLFxuICAgICAgZXhlY3V0aW9uUm9sZSxcbiAgICB9KTtcblxuICAgIGNvbnN0IGxvZ0dyb3VwID0gbmV3IGxvZ3MuTG9nR3JvdXAodGhpcywgJ0xvZ0dyb3VwJywge1xuICAgICAgcmV0ZW50aW9uOiBsb2dzLlJldGVudGlvbkRheXMuT05FX01PTlRILFxuICAgICAgcmVtb3ZhbFBvbGljeTogY2RrLlJlbW92YWxQb2xpY3kuUkVUQUlOLFxuICAgIH0pO1xuXG4gICAgY29uc3QgczNVc2VyID0gbmV3IGlhbS5Vc2VyKHRoaXMsICdTM0tleWNsb2FrVXNlcicpO1xuICAgIGNvbnN0IGFjY2Vzc0tleSA9IG5ldyBpYW0uQWNjZXNzS2V5KHRoaXMsICdTM0tleWNsb2FrVXNlckFjY2Vzc0tleScsIHsgdXNlcjogczNVc2VyIH0pO1xuICAgIHRoaXMua2V5Y2xvYWtVc2VyU2VjcmV0ID0gbmV3IHNlY3JldHNtYW5hZ2VyLlNlY3JldCh0aGlzLCAnUzNLZXljbG9ha1VzZXJTZWNyZXQnLCB7XG4gICAgICBzZWNyZXRTdHJpbmdWYWx1ZTogYWNjZXNzS2V5LnNlY3JldEFjY2Vzc0tleSxcbiAgICB9KTtcbiAgICBzM1BpbmdCdWNrZXQhLmdyYW50UmVhZFdyaXRlKHMzVXNlcik7XG5cbiAgICBjb25zdCBlbnZpcm9ubWVudDoge1trZXk6IHN0cmluZ106IHN0cmluZ30gPSB7XG4gICAgICBKQVZBX09QVFNfQVBQRU5EOiBgXG4gICAgICAtRGpncm91cHMuczMucmVnaW9uX25hbWU9JHtyZWdpb259XG4gICAgICAtRGpncm91cHMuczMuYnVja2V0X25hbWU9JHtzM1BpbmdCdWNrZXQhLmJ1Y2tldE5hbWV9XG4gICAgICAtRGpncm91cHMuczMuYWNjZXNzX2tleT0ke2FjY2Vzc0tleS5hY2Nlc3NLZXlJZH1cbiAgICAgIC1Eamdyb3Vwcy5zMy5zZWNyZXRfYWNjZXNzX2tleT0ke2FjY2Vzc0tleS5zZWNyZXRBY2Nlc3NLZXl9XG4gICAgICBgLnJlcGxhY2UoJ1xcclxcbicsICcnKS5yZXBsYWNlKCdcXG4nLCAnJykucmVwbGFjZSgvXFxzKy9nLCAnICcpLFxuICAgICAgLy8gV2UgaGF2ZSBzZWxlY3RlZCB0aGUgY2FjaGUgc3RhY2sgb2YgJ2VjMicgd2hpY2ggdXNlcyBTM19QSU5HIHVuZGVyIHRoZSBob29kXG4gICAgICAvLyBUaGlzIGlzIHRoZSBBV1MgbmF0aXZlIGNsdXN0ZXIgZGlzY292ZXJ5IGFwcHJvYWNoIGZvciBjYWNoaW5nXG4gICAgICAvLyBTZWU6IGh0dHBzOi8vd3d3LmtleWNsb2FrLm9yZy9zZXJ2ZXIvY2FjaGluZyNfdHJhbnNwb3J0X3N0YWNrc1xuICAgICAgS0NfQ0FDSEVfU1RBQ0s6ICdlYzInLFxuICAgICAgS0NfREI6ICdteXNxbCcsXG4gICAgICBLQ19EQl9VUkxfREFUQUJBU0U6ICdrZXljbG9haycsXG4gICAgICBLQ19EQl9VUkw6IGNvbm5lY3Rpb25TdHJpbmcsXG4gICAgICBLQ19EQl9VUkxfUE9SVDogJzMzMDYnLFxuICAgICAgS0NfREJfVVNFUk5BTUU6ICdhZG1pbicsXG4gICAgICBLQ19IT1NUTkFNRTogcHJvcHMuaG9zdG5hbWUhLFxuICAgICAgS0NfSE9TVE5BTUVfU1RSSUNUX0JBQ0tDSEFOTkVMOiAndHJ1ZScsXG4gICAgICBLQ19QUk9YWTogJ2VkZ2UnLFxuICAgICAgS0NfSEVBTFRIX0VOQUJMRUQ6ICd0cnVlJyxcbiAgICB9O1xuXG4gICAgY29uc3Qga2MgPSB0YXNrRGVmaW5pdGlvbi5hZGRDb250YWluZXIoJ2tleWNsb2FrJywge1xuICAgICAgaW1hZ2UsXG4gICAgICBlbnRyeVBvaW50LFxuICAgICAgZW52aXJvbm1lbnQ6IE9iamVjdC5hc3NpZ24oZW52aXJvbm1lbnQsIHByb3BzLmVudiksXG4gICAgICBzZWNyZXRzLFxuICAgICAgbG9nZ2luZzogZWNzLkxvZ0RyaXZlcnMuYXdzTG9ncyh7XG4gICAgICAgIHN0cmVhbVByZWZpeDogJ2tleWNsb2FrJyxcbiAgICAgICAgbG9nR3JvdXAsXG4gICAgICB9KSxcbiAgICB9KTtcbiAgICBrYy5hZGRQb3J0TWFwcGluZ3MoLi4ucG9ydE1hcHBpbmdzKTtcblxuICAgIC8vIHdlIG5lZWQgZXh0cmEgcHJpdmlsZWdlcyB0byBmZXRjaCBrZXljbG9hayBkb2NrZXIgaW1hZ2VzIGZyb20gQ2hpbmEgbWlycm9yIHNpdGVcbiAgICB0YXNrRGVmaW5pdGlvbi5leGVjdXRpb25Sb2xlPy5hZGRNYW5hZ2VkUG9saWN5KGlhbS5NYW5hZ2VkUG9saWN5LmZyb21Bd3NNYW5hZ2VkUG9saWN5TmFtZSgnQW1hem9uRUMyQ29udGFpbmVyUmVnaXN0cnlSZWFkT25seScpKTtcblxuICAgIHRoaXMuc2VydmljZSA9IG5ldyBlY3MuRmFyZ2F0ZVNlcnZpY2UodGhpcywgJ1NlcnZpY2UnLCB7XG4gICAgICBjbHVzdGVyLFxuICAgICAgdGFza0RlZmluaXRpb24sXG4gICAgICBjaXJjdWl0QnJlYWtlcjogcHJvcHMuY2lyY3VpdEJyZWFrZXIgPyB7IHJvbGxiYWNrOiB0cnVlIH0gOiB1bmRlZmluZWQsXG4gICAgICBkZXNpcmVkQ291bnQ6IHByb3BzLm5vZGVDb3VudCA/PyAyLFxuICAgICAgaGVhbHRoQ2hlY2tHcmFjZVBlcmlvZDogY2RrLkR1cmF0aW9uLnNlY29uZHMoMTIwKSxcbiAgICB9KTtcblxuICAgIHRoaXMuc2VydmljZS5jb25uZWN0aW9ucy5hbGxvd0Zyb20odGhpcy5zZXJ2aWNlLmNvbm5lY3Rpb25zLCBlYzIuUG9ydC50Y3AoNzgwMCksICdrYyBqZ3JvdXBzLXRjcCcpO1xuICAgIHRoaXMuc2VydmljZS5jb25uZWN0aW9ucy5hbGxvd0Zyb20odGhpcy5zZXJ2aWNlLmNvbm5lY3Rpb25zLCBlYzIuUG9ydC50Y3AoNTc4MDApLCAna2Mgamdyb3Vwcy10Y3AtZmQnKTtcbiAgICBzM1BpbmdCdWNrZXQhLmdyYW50UmVhZFdyaXRlKHRhc2tEZWZpbml0aW9uLnRhc2tSb2xlKTtcblxuICAgIGlmIChwcm9wcy5hdXRvU2NhbGVUYXNrKSB7XG4gICAgICBjb25zdCBtaW5DYXBhY2l0eSA9IHByb3BzLmF1dG9TY2FsZVRhc2subWluID8/IHByb3BzLm5vZGVDb3VudCA/PyAyO1xuICAgICAgY29uc3Qgc2NhbGluZyA9IHRoaXMuc2VydmljZS5hdXRvU2NhbGVUYXNrQ291bnQoe1xuICAgICAgICBtaW5DYXBhY2l0eSxcbiAgICAgICAgbWF4Q2FwYWNpdHk6IHByb3BzLmF1dG9TY2FsZVRhc2subWF4ID8/IG1pbkNhcGFjaXR5ICsgNSxcbiAgICAgIH0pO1xuICAgICAgc2NhbGluZy5zY2FsZU9uQ3B1VXRpbGl6YXRpb24oJ0NwdVNjYWxpbmcnLCB7XG4gICAgICAgIHRhcmdldFV0aWxpemF0aW9uUGVyY2VudDogcHJvcHMuYXV0b1NjYWxlVGFzay50YXJnZXRDcHVVdGlsaXphdGlvbiA/PyA3NSxcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICAvLyBsaXN0ZW5lciBwcm90b2NvbCAnVExTJyBpcyBub3Qgc3VwcG9ydGVkIHdpdGggYSB0YXJnZXQgZ3JvdXAgd2l0aCB0aGUgdGFyZ2V0LXR5cGUgJ0FMQidcblxuICAgIHRoaXMuYXBwbGljYXRpb25Mb2FkQmFsYW5jZXIgPSBuZXcgZWxidjIuQXBwbGljYXRpb25Mb2FkQmFsYW5jZXIodGhpcywgJ0FMQicsIHtcbiAgICAgIHZwYyxcbiAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLnB1YmxpY1N1Ym5ldHMsXG4gICAgICBpbnRlcm5ldEZhY2luZzogdHJ1ZSxcbiAgICAgIC8vIHZwY1N1Ym5ldHM6IHByb3BzLmludGVybmV0RmFjaW5nID8gcHJvcHMucHVibGljU3VibmV0cyA6IHByb3BzLnByaXZhdGVTdWJuZXRzLFxuICAgICAgLy8gaW50ZXJuZXRGYWNpbmc6IHByb3BzLmludGVybmV0RmFjaW5nLFxuICAgIH0pO1xuICAgIHByaW50T3V0cHV0KHRoaXMsICdFbmRwb2ludFVSTCcsIGBodHRwczovLyR7dGhpcy5hcHBsaWNhdGlvbkxvYWRCYWxhbmNlci5sb2FkQmFsYW5jZXJEbnNOYW1lfWApO1xuXG4gICAgY29uc3QgbGlzdGVuZXIgPSB0aGlzLmFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyLmFkZExpc3RlbmVyKCdBTEJfSHR0cHNMaXN0ZW5lcicsIHtcbiAgICAgIHByb3RvY29sOiBlbGJ2Mi5BcHBsaWNhdGlvblByb3RvY29sLkhUVFBTLFxuICAgICAgY2VydGlmaWNhdGVzOiBbeyBjZXJ0aWZpY2F0ZUFybjogcHJvcHMuY2VydGlmaWNhdGUuY2VydGlmaWNhdGVBcm4gfV0sXG4gICAgfSk7XG4gICAgLy8gXCJJZiB0aGUgdGFyZ2V0IHR5cGUgaXMgQUxCLCB0aGUgdGFyZ2V0IG11c3QgaGF2ZSBhdCBsZWFzdCBvbmUgbGlzdGVuZXIgdGhhdCBtYXRjaGVzIHRoZSB0YXJnZXQgZ3JvdXAgcG9ydCBvciBhbnkgc3BlY2lmaWVkIHBvcnQgb3ZlcnJpZGVzXG4gICAgbGlzdGVuZXIuYWRkVGFyZ2V0cygnRUNTVGFyZ2V0Jywge1xuICAgICAgcHJvdG9jb2w6IGVsYnYyLkFwcGxpY2F0aW9uUHJvdG9jb2wuSFRUUCxcbiAgICAgIHNsb3dTdGFydDogY2RrLkR1cmF0aW9uLnNlY29uZHMoNjApLFxuICAgICAgc3RpY2tpbmVzc0Nvb2tpZUR1cmF0aW9uOiBwcm9wcy5zdGlja2luZXNzQ29va2llRHVyYXRpb24gPz8gY2RrLkR1cmF0aW9uLmRheXMoMSksXG4gICAgICB0YXJnZXRzOiBbdGhpcy5zZXJ2aWNlXSxcbiAgICAgIGhlYWx0aENoZWNrOiB7XG4gICAgICAgIGhlYWx0aHlUaHJlc2hvbGRDb3VudDogMyxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICAvLyBhbGxvdyB0YXNrIGV4ZWN1dGlvbiByb2xlIHRvIHJlYWQgdGhlIHNlY3JldHNcbiAgICBwcm9wcy5kYXRhYmFzZS5zZWNyZXQuZ3JhbnRSZWFkKHRhc2tEZWZpbml0aW9uLmV4ZWN1dGlvblJvbGUhKTtcbiAgICBwcm9wcy5rZXljbG9ha1NlY3JldC5ncmFudFJlYWQodGFza0RlZmluaXRpb24uZXhlY3V0aW9uUm9sZSEpO1xuXG4gICAgLy8gYWxsb3cgZWNzIHRhc2sgY29ubmVjdCB0byBkYXRhYmFzZVxuICAgIHByb3BzLmRhdGFiYXNlLmNvbm5lY3Rpb25zLmFsbG93RGVmYXVsdFBvcnRGcm9tKHRoaXMuc2VydmljZSk7XG5cblxuICAgIC8vIGNyZWF0ZSBhIGJhc3Rpb24gaG9zdFxuICAgIGlmIChwcm9wcy5iYXN0aW9uID09PSB0cnVlKSB7XG4gICAgICBjb25zdCBiYXN0ID0gbmV3IGVjMi5CYXN0aW9uSG9zdExpbnV4KHRoaXMsICdCYXN0Jywge1xuICAgICAgICB2cGMsXG4gICAgICAgIGluc3RhbmNlVHlwZTogbmV3IGVjMi5JbnN0YW5jZVR5cGUoJ3QzLnNtYWxsJyksXG4gICAgICB9KTtcbiAgICAgIHByb3BzLmRhdGFiYXNlLmNvbm5lY3Rpb25zLmFsbG93RGVmYXVsdFBvcnRGcm9tKGJhc3QpO1xuICAgIH1cbiAgfVxuICBwcml2YXRlIGdldEltYWdlVXJpRnJvbU1hcChtYXA6IGRvY2tlckltYWdlTWFwLCB2ZXJzaW9uOiBzdHJpbmcsIGlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIGNvbnN0IHN0YWNrID0gY2RrLlN0YWNrLm9mKHRoaXMpO1xuICAgIGlmIChjZGsuVG9rZW4uaXNVbnJlc29sdmVkKHN0YWNrLnJlZ2lvbikpIHtcbiAgICAgIGNvbnN0IG1hcHBpbmc6IHsgW2sxOiBzdHJpbmddOiB7IFtrMjogc3RyaW5nXTogYW55IH0gfSA9IHt9O1xuICAgICAgZm9yIChsZXQgW3BhcnRpdGlvbiwgdXJpXSBvZiBPYmplY3QuZW50cmllcyhtYXApKSB7XG4gICAgICAgIHVyaSArPSB2ZXJzaW9uO1xuICAgICAgICBtYXBwaW5nW3BhcnRpdGlvbl0gPSB7IHVyaSB9O1xuICAgICAgfVxuICAgICAgY29uc3QgaW1hZ2VNYXAgPSBuZXcgY2RrLkNmbk1hcHBpbmcodGhpcywgaWQsIHsgbWFwcGluZyB9KTtcbiAgICAgIHJldHVybiBpbWFnZU1hcC5maW5kSW5NYXAoY2RrLkF3cy5QQVJUSVRJT04sICd1cmknKTtcbiAgICB9IGVsc2Uge1xuICAgICAgaWYgKHN0YWNrLnJlZ2lvbi5zdGFydHNXaXRoKCdjbi0nKSkge1xuICAgICAgICByZXR1cm4gbWFwWydhd3MtY24nXSArPSB2ZXJzaW9uO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIG1hcC5hd3MgKz0gdmVyc2lvbjtcbiAgICAgIH1cbiAgICB9XG4gIH1cbiAgcHJpdmF0ZSBnZXRLZXlDbG9ha0RvY2tlckltYWdlVXJpKHZlcnNpb246IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIHRoaXMuZ2V0SW1hZ2VVcmlGcm9tTWFwKEtFWUNMT0FLX0RPQ0tFUl9JTUFHRV9VUklfTUFQLCB2ZXJzaW9uLCAnS2V5Y2xvYWtJbWFnZU1hcCcpO1xuICB9XG59XG5cbi8qKlxuICogQ3JlYXRlIG9yIGltcG9ydCBWUENcbiAqIEBwYXJhbSBzY29wZSB0aGUgY2RrIHNjb3BlXG4gKi9cbmZ1bmN0aW9uIGdldE9yQ3JlYXRlVnBjKHNjb3BlOiBDb25zdHJ1Y3QpOiBlYzIuSVZwYyB7XG4gIC8vIHVzZSBhbiBleGlzdGluZyB2cGMgb3IgY3JlYXRlIGEgbmV3IG9uZVxuICByZXR1cm4gc2NvcGUubm9kZS50cnlHZXRDb250ZXh0KCd1c2VfZGVmYXVsdF92cGMnKSA9PT0gJzEnID9cbiAgICBlYzIuVnBjLmZyb21Mb29rdXAoc2NvcGUsICdWcGMnLCB7IGlzRGVmYXVsdDogdHJ1ZSB9KSA6XG4gICAgc2NvcGUubm9kZS50cnlHZXRDb250ZXh0KCd1c2VfdnBjX2lkJykgP1xuICAgICAgZWMyLlZwYy5mcm9tTG9va3VwKHNjb3BlLCAnVnBjJywgeyB2cGNJZDogc2NvcGUubm9kZS50cnlHZXRDb250ZXh0KCd1c2VfdnBjX2lkJykgfSkgOlxuICAgICAgbmV3IGVjMi5WcGMoc2NvcGUsICdWcGMnLCB7IG1heEF6czogMywgbmF0R2F0ZXdheXM6IDEgfSk7XG59XG5cbmZ1bmN0aW9uIHByaW50T3V0cHV0KHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIGtleTogc3RyaW5nIHwgbnVtYmVyKSB7XG4gIG5ldyBjZGsuQ2ZuT3V0cHV0KHNjb3BlLCBpZCwgeyB2YWx1ZTogU3RyaW5nKGtleSkgfSk7XG59XG4iXX0=