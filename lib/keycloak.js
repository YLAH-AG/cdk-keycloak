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
            cpu: 2048,
            memoryLimitMiB: 4096,
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoia2V5Y2xvYWsuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMva2V5Y2xvYWsudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSxtQ0FBbUM7QUFDbkMsNkNBU3FCO0FBQ3JCLDJDQUF1QztBQUV2Qyw4Q0FBOEM7QUFDOUMsc0hBQXNIO0FBQ3RILE1BQU0sbUNBQW1DLEdBQUc7SUFDMUMsV0FBVztJQUNYLFdBQVc7SUFDWCxXQUFXO0lBQ1gsV0FBVztJQUNYLFlBQVk7SUFDWixnQkFBZ0I7SUFDaEIsZ0JBQWdCO0lBQ2hCLGdCQUFnQjtJQUNoQixnQkFBZ0I7SUFDaEIsY0FBYztJQUNkLGNBQWM7SUFDZCxXQUFXO0lBQ1gsV0FBVztJQUNYLFdBQVc7SUFDWCxnQkFBZ0I7Q0FDakIsQ0FBQztBQUVGOztHQUVHO0FBQ0gsTUFBYSxlQUFlO0lBNkQxQjs7O09BR0c7SUFDSCxZQUFvQyxPQUFlO1FBQWYsWUFBTyxHQUFQLE9BQU8sQ0FBUTtJQUFJLENBQUM7SUFUeEQ7OztPQUdHO0lBQ0ksTUFBTSxDQUFDLEVBQUUsQ0FBQyxPQUFlLElBQUksT0FBTyxJQUFJLGVBQWUsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUM7O0FBNUQ1RSwwQ0FrRUM7OztBQWpFQzs7R0FFRztBQUNvQix1QkFBTyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUM7QUFFOUQ7O0dBRUc7QUFDb0IsdUJBQU8sR0FBRyxlQUFlLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBRTlEOztHQUVHO0FBQ29CLHVCQUFPLEdBQUcsZUFBZSxDQUFDLEVBQUUsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUU5RDs7R0FFRztBQUNvQix1QkFBTyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUM7QUFFOUQ7O0dBRUc7QUFDb0IsdUJBQU8sR0FBRyxlQUFlLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBRTlE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Y2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBjZGsgZnJvbSAnYXdzLWNkay1saWInO1xuaW1wb3J0IHtcbiAgYXdzX2NlcnRpZmljYXRlbWFuYWdlciBhcyBjZXJ0bWdyLFxuICBhd3NfZWMyIGFzIGVjMiwgYXdzX2VjcyBhcyBlY3MsIGF3c19lbGFzdGljbG9hZGJhbGFuY2luZ3YyIGFzIGVsYnYyLFxuICAvLyBhd3NfZWxhc3RpY2xvYWRiYWxhbmNpbmd2Ml90YXJnZXRzIGFzIGVsYlRhcmdldHMsXG4gIGF3c19pYW0gYXMgaWFtLFxuICBhd3NfbG9ncyBhcyBsb2dzLFxuICBhd3NfcmRzIGFzIHJkcyxcbiAgYXdzX3MzIGFzIHMzLFxuICBhd3Nfc2VjcmV0c21hbmFnZXIgYXMgc2VjcmV0c21hbmFnZXIsXG59IGZyb20gJ2F3cy1jZGstbGliJztcbmltcG9ydCB7IENvbnN0cnVjdCB9IGZyb20gJ2NvbnN0cnVjdHMnO1xuXG4vLyByZWdpb25hbCBhdmFpbGliaWxpdHkgZm9yIGF1cm9yYSBzZXJ2ZXJsZXNzXG4vLyBzZWUgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL0FtYXpvblJEUy9sYXRlc3QvQXVyb3JhVXNlckd1aWRlL0NvbmNlcHRzLkF1cm9yYUZlYXR1cmVzUmVnaW9uc0RCRW5naW5lcy5ncmlkcy5odG1sXG5jb25zdCBBVVJPUkFfU0VSVkVSTEVTU19TVVBQT1JURURfUkVHSU9OUyA9IFtcbiAgJ3VzLWVhc3QtMScsXG4gICd1cy1lYXN0LTInLFxuICAndXMtd2VzdC0xJyxcbiAgJ3VzLXdlc3QtMicsXG4gICdhcC1zb3V0aC0xJyxcbiAgJ2FwLW5vcnRoZWFzdC0xJyxcbiAgJ2FwLW5vcnRoZWFzdC0yJyxcbiAgJ2FwLXNvdXRoZWFzdC0xJyxcbiAgJ2FwLXNvdXRoZWFzdC0yJyxcbiAgJ2NhLWNlbnRyYWwtMScsXG4gICdldS1jZW50cmFsLTEnLFxuICAnZXUtd2VzdC0xJyxcbiAgJ2V1LXdlc3QtMicsXG4gICdldS13ZXN0LTMnLFxuICAnY24tbm9ydGh3ZXN0LTEnLFxuXTtcblxuLyoqXG4gKiBLZXljbG9hayAgdmVyc2lvblxuICovXG5leHBvcnQgY2xhc3MgS2V5Y2xvYWtWZXJzaW9uIHtcbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTIuMC40XG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxMl8wXzQgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzEyLjAuNCcpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE1LjAuMFxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTVfMF8wID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxNS4wLjAnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxNS4wLjFcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE1XzBfMSA9IEtleWNsb2FrVmVyc2lvbi5vZignMTUuMC4xJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTUuMC4yXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxNV8wXzIgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE1LjAuMicpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE2LjEuMVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTZfMV8xID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxNi4xLjEnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAxNy4wLjFcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjE3XzBfMSA9IEtleWNsb2FrVmVyc2lvbi5vZignMTcuMC4xJyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMTguMC4yXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYxOF8wXzMgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzE4LjAuMicpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDE5LjAuM1xuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMTlfMF8zID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcxOS4wLjMnKTtcblxuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiAyMC4wLjVcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVjIwXzBfMyA9IEtleWNsb2FrVmVyc2lvbi5vZignMjAuMC41Jyk7XG5cbiAgLyoqXG4gICAqIEtleWNsb2FrIHZlcnNpb24gMjEuMC4wXG4gICAqL1xuICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFYyMV8wXzAgPSBLZXljbG9ha1ZlcnNpb24ub2YoJzIxLjAuMCcpO1xuXG4gIC8qKlxuICAgKiBLZXljbG9hayB2ZXJzaW9uIDIxLjAuMVxuICAgKi9cbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBWMjFfMF8xID0gS2V5Y2xvYWtWZXJzaW9uLm9mKCcyMS4wLjEnKTtcblxuICAvKipcbiAgICogQ3VzdG9tIGNsdXN0ZXIgdmVyc2lvblxuICAgKiBAcGFyYW0gdmVyc2lvbiBjdXN0b20gdmVyc2lvbiBudW1iZXJcbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgb2YodmVyc2lvbjogc3RyaW5nKSB7IHJldHVybiBuZXcgS2V5Y2xvYWtWZXJzaW9uKHZlcnNpb24pOyB9XG4gIC8qKlxuICAgKlxuICAgKiBAcGFyYW0gdmVyc2lvbiBjbHVzdGVyIHZlcnNpb24gbnVtYmVyXG4gICAqL1xuICBwcml2YXRlIGNvbnN0cnVjdG9yKHB1YmxpYyByZWFkb25seSB2ZXJzaW9uOiBzdHJpbmcpIHsgfVxufVxuXG5pbnRlcmZhY2UgZG9ja2VySW1hZ2VNYXAge1xuICAnYXdzJzogc3RyaW5nO1xuICAnYXdzLWNuJzogc3RyaW5nO1xufVxuXG5jb25zdCBLRVlDTE9BS19ET0NLRVJfSU1BR0VfVVJJX01BUDogZG9ja2VySW1hZ2VNYXAgPSB7XG4gICdhd3MnOiAncXVheS5pby9rZXljbG9hay9rZXljbG9hazonLFxuICAnYXdzLWNuJzogJzA0ODkxMjA2MDkxMC5ka3IuZWNyLmNuLW5vcnRod2VzdC0xLmFtYXpvbmF3cy5jb20uY24vZG9ja2VyaHViL2pib3NzL2tleWNsb2FrOicsXG59O1xuXG4vKipcbiAqIFRoZSBFQ1MgdGFzayBhdXRvc2NhbGluZyBkZWZpbml0aW9uXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgQXV0b1NjYWxlVGFzayB7XG4gIC8qKlxuICAgKiBUaGUgbWluaW1hbCBjb3VudCBvZiB0aGUgdGFzayBudW1iZXJcbiAgICpcbiAgICogQGRlZmF1bHQgLSBub2RlQ291bnRcbiAgICovXG4gIHJlYWRvbmx5IG1pbj86IG51bWJlcjtcbiAgLyoqXG4gICAqIFRoZSBtYXhpbWFsIGNvdW50IG9mIHRoZSB0YXNrIG51bWJlclxuICAgKlxuICAgKiBAZGVmYXVsdCAtIG1pbiArIDVcbiAgICovXG4gIHJlYWRvbmx5IG1heD86IG51bWJlcjtcbiAgLyoqXG4gICAqIFRoZSB0YXJnZXQgY3B1IHV0aWxpemF0aW9uIGZvciB0aGUgc2VydmljZSBhdXRvc2NhbGluZ1xuICAgKlxuICAgKiBAZGVmYXVsdCA3NVxuICAgKi9cbiAgcmVhZG9ubHkgdGFyZ2V0Q3B1VXRpbGl6YXRpb24/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgS2V5Q2xvYWtQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgS2V5Y2xvYWsgdmVyc2lvbiBmb3IgdGhlIGNsdXN0ZXIuXG4gICAqL1xuICByZWFkb25seSBrZXljbG9ha1ZlcnNpb246IEtleWNsb2FrVmVyc2lvbjtcbiAgLyoqXG4gICAqIFRoZSBlbnZpcm9ubWVudCB2YXJpYWJsZXMgdG8gcGFzcyB0byB0aGUga2V5Y2xvYWsgY29udGFpbmVyXG4gICAqL1xuICByZWFkb25seSBlbnY/OiB7IFtrZXk6IHN0cmluZ106IHN0cmluZyB9O1xuICAvKipcbiAgICogVlBDIGZvciB0aGUgd29ya2xvYWRcbiAgICovXG4gIHJlYWRvbmx5IHZwYz86IGVjMi5JVnBjO1xuICAvKipcbiAgICogQUNNIGNlcnRpZmljYXRlIEFSTiB0byBpbXBvcnRcbiAgICovXG4gIHJlYWRvbmx5IGNlcnRpZmljYXRlQXJuOiBzdHJpbmc7XG4gIC8qKlxuICAgKiBDcmVhdGUgYSBiYXN0aW9uIGhvc3QgZm9yIGRlYnVnZ2luZyBvciB0cm91YmxlLXNob290aW5nXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBiYXN0aW9uPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIE51bWJlciBvZiBrZXljbG9hayBub2RlIGluIHRoZSBjbHVzdGVyXG4gICAqXG4gICAqIEBkZWZhdWx0IDJcbiAgICovXG4gIHJlYWRvbmx5IG5vZGVDb3VudD86IG51bWJlcjtcbiAgLyoqXG4gICAqIFZQQyBwdWJsaWMgc3VibmV0cyBmb3IgQUxCXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gVlBDIHB1YmxpYyBzdWJuZXRzXG4gICAqL1xuICByZWFkb25seSBwdWJsaWNTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIFZQQyBwcml2YXRlIHN1Ym5ldHMgZm9yIGtleWNsb2FrIHNlcnZpY2VcbiAgICpcbiAgICogQGRlZmF1bHQgLSBWUEMgcHJpdmF0ZSBzdWJuZXRzXG4gICAqL1xuICByZWFkb25seSBwcml2YXRlU3VibmV0cz86IGVjMi5TdWJuZXRTZWxlY3Rpb247XG4gIC8qKlxuICAgKiBWUEMgc3VibmV0cyBmb3IgZGF0YWJhc2VcbiAgICpcbiAgICogQGRlZmF1bHQgLSBWUEMgaXNvbGF0ZWQgc3VibmV0c1xuICAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2VTdWJuZXRzPzogZWMyLlN1Ym5ldFNlbGVjdGlvbjtcbiAgLyoqXG4gICAqIERhdGFiYXNlIGluc3RhbmNlIHR5cGVcbiAgICpcbiAgICogQGRlZmF1bHQgcjUubGFyZ2VcbiAgICovXG4gIHJlYWRvbmx5IGRhdGFiYXNlSW5zdGFuY2VUeXBlPzogZWMyLkluc3RhbmNlVHlwZTtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBpbnN0YW5jZSBlbmdpbmVcbiAgICpcbiAgICogQGRlZmF1bHQgLSBNeVNRTCA4LjAuMjFcbiAgICovXG4gIHJlYWRvbmx5IGluc3RhbmNlRW5naW5lPzogcmRzLklJbnN0YW5jZUVuZ2luZTtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBjbHVzdGVyIGVuZ2luZVxuICAgKlxuICAgKiBAZGVmYXVsdCByZHMuQXVyb3JhTXlzcWxFbmdpbmVWZXJzaW9uLlZFUl8yXzA5XzFcbiAgICovXG4gIHJlYWRvbmx5IGNsdXN0ZXJFbmdpbmU/OiByZHMuSUNsdXN0ZXJFbmdpbmU7XG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHVzZSBhdXJvcmEgc2VydmVybGVzcy4gV2hlbiBlbmFibGVkLCB0aGUgYGRhdGFiYXNlSW5zdGFuY2VUeXBlYCBhbmRcbiAgICogYGVuZ2luZWAgd2lsbCBiZSBpZ25vcmVkLiBUaGUgYHJkcy5EYXRhYmFzZUNsdXN0ZXJFbmdpbmUuQVVST1JBX01ZU1FMYCB3aWxsIGJlIHVzZWQgYXNcbiAgICogdGhlIGRlZmF1bHQgY2x1c3RlciBlbmdpbmUgaW5zdGVhZC5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGF1cm9yYVNlcnZlcmxlc3M/OiBib29sZWFuO1xuICAvKipcbiAgICogV2hldGhlciB0byB1c2UgYXVyb3JhIHNlcnZlcmxlc3MgdjIuIFdoZW4gZW5hYmxlZCwgdGhlIGBkYXRhYmFzZUluc3RhbmNlVHlwZWAgd2lsbCBiZSBpZ25vcmVkLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYXVyb3JhU2VydmVybGVzc1YyPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gdXNlIHNpbmdsZSBSRFMgaW5zdGFuY2UgcmF0aGVyIHRoYW4gUkRTIGNsdXN0ZXIuIE5vdCByZWNvbW1lbmRlZCBmb3IgcHJvZHVjdGlvbi5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IHNpbmdsZURiSW5zdGFuY2U/OiBib29sZWFuO1xuICAvKipcbiAgICogZGF0YWJhc2UgYmFja3VwIHJldGVuc2lvblxuICAgKlxuICAgKiBAZGVmYXVsdCAtIDcgZGF5c1xuICAgKi9cbiAgcmVhZG9ubHkgYmFja3VwUmV0ZW50aW9uPzogY2RrLkR1cmF0aW9uO1xuICAvKipcbiAgICogVGhlIHN0aWNreSBzZXNzaW9uIGR1cmF0aW9uIGZvciB0aGUga2V5Y2xvYWsgd29ya2xvYWQgd2l0aCBBTEIuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gb25lIGRheVxuICAgKi9cbiAgcmVhZG9ubHkgc3RpY2tpbmVzc0Nvb2tpZUR1cmF0aW9uPzogY2RrLkR1cmF0aW9uO1xuICAvKipcbiAgICogQXV0b3NjYWxpbmcgZm9yIHRoZSBFQ1MgU2VydmljZVxuICAgKlxuICAgKiBAZGVmYXVsdCAtIG5vIGVjcyBzZXJ2aWNlIGF1dG9zY2FsaW5nXG4gICAqL1xuICByZWFkb25seSBhdXRvU2NhbGVUYXNrPzogQXV0b1NjYWxlVGFzaztcblxuICAvKipcbiAgICogV2hldGhlciB0byBwdXQgdGhlIGxvYWQgYmFsYW5jZXIgaW4gdGhlIHB1YmxpYyBvciBwcml2YXRlIHN1Ym5ldHNcbiAgICpcbiAgICogQGRlZmF1bHQgdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgaW50ZXJuZXRGYWNpbmc/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBUaGUgaG9zdG5hbWUgdG8gdXNlIGZvciB0aGUga2V5Y2xvYWsgc2VydmVyXG4gICAqL1xuICByZWFkb25seSBob3N0bmFtZT86IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIG1pbmltdW0gbnVtYmVyIG9mIEF1cm9yYSBTZXJ2ZXJsZXNzIFYyIGNhcGFjaXR5IHVuaXRzLlxuICAgKlxuICAgKiBAZGVmYXVsdCAwLjVcbiAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2VNaW5DYXBhY2l0eT86IG51bWJlcjtcblxuICAvKipcbiAgKiBUaGUgbWF4aW11bSBudW1iZXIgb2YgQXVyb3JhIFNlcnZlcmxlc3MgVjIgY2FwYWNpdHkgdW5pdHMuXG4gICpcbiAgICogQGRlZmF1bHQgMTBcbiAgICovXG4gIHJlYWRvbmx5IGRhdGFiYXNlTWF4Q2FwYWNpdHk/OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIENvbnRyb2xzIHdoYXQgaGFwcGVucyB0byB0aGUgZGF0YWJhc2UgaWYgaXQgc3RvcHMgYmVpbmcgbWFuYWdlZCBieSBDbG91ZEZvcm1hdGlvblxuICAgKlxuICAgKiBAZGVmYXVsdCBSZW1vdmFsUG9saWN5LlJFVEFJTlxuICAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2VSZW1vdmFsUG9saWN5PzogY2RrLlJlbW92YWxQb2xpY3k7XG5cblxuICAvKipcbiAgICogT3ZlcnJpZGVzIHRoZSBkZWZhdWx0IGltYWdlXG4gICAqXG4gICAqIEBkZWZhdWx0IHF1YXkuaW8va2V5Y2xvYWsva2V5Y2xvYWs6JHtLRVlDTE9BS19WRVJTSU9OfVxuICAgKi9cbiAgcmVhZG9ubHkgY29udGFpbmVySW1hZ2U/OiBlY3MuQ29udGFpbmVySW1hZ2U7XG59XG5cbmV4cG9ydCBjbGFzcyBLZXlDbG9hayBleHRlbmRzIENvbnN0cnVjdCB7XG4gIHJlYWRvbmx5IHZwYzogZWMyLklWcGM7XG4gIHJlYWRvbmx5IGRiPzogRGF0YWJhc2U7XG4gIHJlYWRvbmx5IGFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyOiBlbGJ2Mi5BcHBsaWNhdGlvbkxvYWRCYWxhbmNlcjtcbiAgLy8gcmVhZG9ubHkgbmV0d29ya0xvYWRCYWxhbmNlcjogZWxidjIuTmV0d29ya0xvYWRCYWxhbmNlcjtcbiAgcmVhZG9ubHkga2V5Y2xvYWtTZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBLZXlDbG9ha1Byb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkKTtcblxuICAgIGNvbnN0IHJlZ2lvbiA9IGNkay5TdGFjay5vZih0aGlzKS5yZWdpb247XG4gICAgY29uc3QgcmVnaW9uSXNSZXNvbHZlZCA9ICFjZGsuVG9rZW4uaXNVbnJlc29sdmVkKHJlZ2lvbik7XG5cbiAgICBpZiAocHJvcHMuYXVyb3JhU2VydmVybGVzcyAmJiByZWdpb25Jc1Jlc29sdmVkICYmICFBVVJPUkFfU0VSVkVSTEVTU19TVVBQT1JURURfUkVHSU9OUy5pbmNsdWRlcyhyZWdpb24pKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYEF1cm9yYSBzZXJ2ZXJsZXNzIGlzIG5vdCBzdXBwb3J0ZWQgaW4gJHtyZWdpb259YCk7XG4gICAgfVxuXG4gICAgdGhpcy5rZXljbG9ha1NlY3JldCA9IHRoaXMuX2dlbmVyYXRlS2V5Y2xvYWtTZWNyZXQoKTtcbiAgICB0aGlzLnZwYyA9IHByb3BzLnZwYyA/PyBnZXRPckNyZWF0ZVZwYyh0aGlzKTtcblxuICAgIHRoaXMuZGIgPSB0aGlzLmFkZERhdGFiYXNlKHtcbiAgICAgIHZwYzogdGhpcy52cGMsXG4gICAgICBkYXRhYmFzZVN1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgIGluc3RhbmNlVHlwZTogcHJvcHMuZGF0YWJhc2VJbnN0YW5jZVR5cGUsXG4gICAgICBpbnN0YW5jZUVuZ2luZTogcHJvcHMuaW5zdGFuY2VFbmdpbmUsXG4gICAgICBjbHVzdGVyRW5naW5lOiBwcm9wcy5jbHVzdGVyRW5naW5lLFxuICAgICAgYXVyb3JhU2VydmVybGVzczogZmFsc2UsXG4gICAgICBhdXJvcmFTZXJ2ZXJsZXNzVjI6IGZhbHNlLFxuICAgICAgc2luZ2xlRGJJbnN0YW5jZTogcHJvcHMuc2luZ2xlRGJJbnN0YW5jZSxcbiAgICAgIGJhY2t1cFJldGVudGlvbjogcHJvcHMuYmFja3VwUmV0ZW50aW9uLFxuICAgICAgbWF4Q2FwYWNpdHk6IHByb3BzLmRhdGFiYXNlTWF4Q2FwYWNpdHksXG4gICAgICBtaW5DYXBhY2l0eTogcHJvcHMuZGF0YWJhc2VNaW5DYXBhY2l0eSxcbiAgICAgIHJlbW92YWxQb2xpY3k6IHByb3BzLmRhdGFiYXNlUmVtb3ZhbFBvbGljeSxcbiAgICB9KTtcbiAgICBjb25zdCBrZXljbG9ha0NvbnRhaW5lclNlcnZpY2UgPSB0aGlzLmFkZEtleUNsb2FrQ29udGFpbmVyU2VydmljZSh7XG4gICAgICBkYXRhYmFzZTogdGhpcy5kYixcbiAgICAgIHZwYzogdGhpcy52cGMsXG4gICAgICBrZXljbG9ha1ZlcnNpb246IHByb3BzLmtleWNsb2FrVmVyc2lvbixcbiAgICAgIHB1YmxpY1N1Ym5ldHM6IHByb3BzLnB1YmxpY1N1Ym5ldHMsXG4gICAgICBwcml2YXRlU3VibmV0czogcHJvcHMucHJpdmF0ZVN1Ym5ldHMsXG4gICAgICBrZXljbG9ha1NlY3JldDogdGhpcy5rZXljbG9ha1NlY3JldCxcbiAgICAgIGNlcnRpZmljYXRlOiBjZXJ0bWdyLkNlcnRpZmljYXRlLmZyb21DZXJ0aWZpY2F0ZUFybih0aGlzLCAnQUNNQ2VydCcsIHByb3BzLmNlcnRpZmljYXRlQXJuKSxcbiAgICAgIGJhc3Rpb246IHByb3BzLmJhc3Rpb24sXG4gICAgICBub2RlQ291bnQ6IHByb3BzLm5vZGVDb3VudCxcbiAgICAgIHN0aWNraW5lc3NDb29raWVEdXJhdGlvbjogcHJvcHMuc3RpY2tpbmVzc0Nvb2tpZUR1cmF0aW9uLFxuICAgICAgYXV0b1NjYWxlVGFzazogcHJvcHMuYXV0b1NjYWxlVGFzayxcbiAgICAgIGVudjogcHJvcHMuZW52LFxuICAgICAgaW50ZXJuZXRGYWNpbmc6IHByb3BzLmludGVybmV0RmFjaW5nID8/IHRydWUsXG4gICAgICBob3N0bmFtZTogcHJvcHMuaG9zdG5hbWUsXG4gICAgICBjb250YWluZXJJbWFnZTogcHJvcHMuY29udGFpbmVySW1hZ2UsXG4gICAgfSk7XG5cbiAgICB0aGlzLmFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyID0ga2V5Y2xvYWtDb250YWluZXJTZXJ2aWNlLmFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyO1xuICAgIC8vIHRoaXMubmV0d29ya0xvYWRCYWxhbmNlciA9IGtleWNsb2FrQ29udGFpbmVyU2VydmljZS5uZXR3b3JrTG9hZEJhbGFuY2VyO1xuICAgIGlmICghY2RrLlN0YWNrLm9mKHRoaXMpLnRlbXBsYXRlT3B0aW9ucy5kZXNjcmlwdGlvbikge1xuICAgICAgY2RrLlN0YWNrLm9mKHRoaXMpLnRlbXBsYXRlT3B0aW9ucy5kZXNjcmlwdGlvbiA9ICcoU084MDIxKSAtIERlcGxveSBrZXljbG9hayBvbiBBV1Mgd2l0aCBjZGsta2V5Y2xvYWsgY29uc3RydWN0IGxpYnJhcnknO1xuICAgIH1cbiAgfVxuICBwdWJsaWMgYWRkRGF0YWJhc2UocHJvcHM6IERhdGFiYXNlUHJvcHMpOiBEYXRhYmFzZSB7XG4gICAgcmV0dXJuIG5ldyBEYXRhYmFzZSh0aGlzLCAnRGF0YWJhc2UnLCBwcm9wcyk7XG4gIH1cbiAgcHVibGljIGFkZEtleUNsb2FrQ29udGFpbmVyU2VydmljZShwcm9wczogQ29udGFpbmVyU2VydmljZVByb3BzKSB7XG4gICAgcmV0dXJuIG5ldyBDb250YWluZXJTZXJ2aWNlKHRoaXMsICdLZXlDbG9ha0NvbnRhaW5lclNlcml2Y2UnLCBwcm9wcyk7XG4gIH1cbiAgcHJpdmF0ZSBfZ2VuZXJhdGVLZXljbG9ha1NlY3JldCgpOiBzZWNyZXRzbWFuYWdlci5JU2VjcmV0IHtcbiAgICByZXR1cm4gbmV3IHNlY3JldHNtYW5hZ2VyLlNlY3JldCh0aGlzLCAnS0NTZWNyZXQnLCB7XG4gICAgICBnZW5lcmF0ZVNlY3JldFN0cmluZzoge1xuICAgICAgICBnZW5lcmF0ZVN0cmluZ0tleTogJ3Bhc3N3b3JkJyxcbiAgICAgICAgZXhjbHVkZVB1bmN0dWF0aW9uOiB0cnVlLFxuICAgICAgICBwYXNzd29yZExlbmd0aDogMTIsXG4gICAgICAgIHNlY3JldFN0cmluZ1RlbXBsYXRlOiBKU09OLnN0cmluZ2lmeSh7IHVzZXJuYW1lOiAna2V5Y2xvYWsnIH0pLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxufVxuXG5leHBvcnQgaW50ZXJmYWNlIERhdGFiYXNlUHJvcHMge1xuICAvKipcbiAgICogVGhlIFZQQyBmb3IgdGhlIGRhdGFiYXNlXG4gICAqL1xuICByZWFkb25seSB2cGM6IGVjMi5JVnBjO1xuICAvKipcbiAgICogVlBDIHN1Ym5ldHMgZm9yIGRhdGFiYXNlXG4gICAqL1xuICByZWFkb25seSBkYXRhYmFzZVN1Ym5ldHM/OiBlYzIuU3VibmV0U2VsZWN0aW9uO1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIGluc3RhbmNlIHR5cGVcbiAgICpcbiAgICogQGRlZmF1bHQgcjUubGFyZ2VcbiAgICovXG4gIHJlYWRvbmx5IGluc3RhbmNlVHlwZT86IGVjMi5JbnN0YW5jZVR5cGU7XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2UgaW5zdGFuY2UgZW5naW5lXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTXlTUUwgOC4wLjIxXG4gICAqL1xuICByZWFkb25seSBpbnN0YW5jZUVuZ2luZT86IHJkcy5JSW5zdGFuY2VFbmdpbmU7XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2UgY2x1c3RlciBlbmdpbmVcbiAgICpcbiAgICogQGRlZmF1bHQgcmRzLkF1cm9yYU15c3FsRW5naW5lVmVyc2lvbi5WRVJfMl8wOV8xXG4gICAqL1xuICByZWFkb25seSBjbHVzdGVyRW5naW5lPzogcmRzLklDbHVzdGVyRW5naW5lO1xuICAvKipcbiAgICogZW5hYmxlIGF1cm9yYSBzZXJ2ZXJsZXNzXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBhdXJvcmFTZXJ2ZXJsZXNzPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIGVuYWJsZSBhdXJvcmEgc2VydmVybGVzcyB2MlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYXVyb3JhU2VydmVybGVzc1YyPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogV2hldGhlciB0byB1c2Ugc2luZ2xlIFJEUyBpbnN0YW5jZSByYXRoZXIgdGhhbiBSRFMgY2x1c3Rlci4gTm90IHJlY29tbWVuZGVkIGZvciBwcm9kdWN0aW9uLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgc2luZ2xlRGJJbnN0YW5jZT86IGJvb2xlYW47XG4gIC8qKlxuICAgKiBkYXRhYmFzZSBiYWNrdXAgcmV0ZW5zaW9uXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gNyBkYXlzXG4gICAqL1xuICByZWFkb25seSBiYWNrdXBSZXRlbnRpb24/OiBjZGsuRHVyYXRpb247XG4gIC8qKlxuICAgKiBUaGUgbWluaW11bSBudW1iZXIgb2YgQXVyb3JhIFNlcnZlcmxlc3MgVjIgY2FwYWNpdHkgdW5pdHMuXG4gICAqXG4gICAqIEBkZWZhdWx0IDAuNVxuICAqL1xuICByZWFkb25seSBtaW5DYXBhY2l0eT86IG51bWJlcjtcbiAgLyoqXG4gICAqIFRoZSBtYXhpbXVtIG51bWJlciBvZiBBdXJvcmEgU2VydmVybGVzcyBWMiBjYXBhY2l0eSB1bml0cy5cbiAgICpcbiAgICogQGRlZmF1bHQgMTBcbiAgICovXG4gIHJlYWRvbmx5IG1heENhcGFjaXR5PzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBDb250cm9scyB3aGF0IGhhcHBlbnMgdG8gdGhlIGRhdGFiYXNlIGlmIGl0IHN0b3BzIGJlaW5nIG1hbmFnZWQgYnkgQ2xvdWRGb3JtYXRpb25cbiAgICpcbiAgICogQGRlZmF1bHQgUmVtb3ZhbFBvbGljeS5SRVRBSU5cbiAgICovXG4gIHJlYWRvbmx5IHJlbW92YWxQb2xpY3k/OiBjZGsuUmVtb3ZhbFBvbGljeTtcbn1cblxuLyoqXG4gKiBEYXRhYmFzZSBjb25maWd1cmF0aW9uXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgRGF0YWJhc2VDb25maWcge1xuICAvKipcbiAgICogVGhlIGRhdGFiYXNlIHNlY3JldC5cbiAgICovXG4gIHJlYWRvbmx5IHNlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgLyoqXG4gICAqIFRoZSBkYXRhYmFzZSBjb25ubmVjdGlvbnMuXG4gICAqL1xuICByZWFkb25seSBjb25uZWN0aW9uczogZWMyLkNvbm5lY3Rpb25zO1xuICAvKipcbiAgICogVGhlIGVuZHBvaW50IGFkZHJlc3MgZm9yIHRoZSBkYXRhYmFzZS5cbiAgICovXG4gIHJlYWRvbmx5IGVuZHBvaW50OiBzdHJpbmc7XG4gIC8qKlxuICAgKiBUaGUgZGF0YWJhc2FlIGlkZW50aWZpZXIuXG4gICAqL1xuICByZWFkb25seSBpZGVudGlmaWVyOiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyB0aGUgZGF0YWJhc2UgaW5zdGFuY2Ugb3IgZGF0YWJhc2UgY2x1c3RlclxuICovXG5leHBvcnQgY2xhc3MgRGF0YWJhc2UgZXh0ZW5kcyBDb25zdHJ1Y3Qge1xuICByZWFkb25seSB2cGM6IGVjMi5JVnBjO1xuICByZWFkb25seSBjbHVzdGVyRW5kcG9pbnRIb3N0bmFtZTogc3RyaW5nO1xuICByZWFkb25seSBjbHVzdGVySWRlbnRpZmllcjogc3RyaW5nO1xuICByZWFkb25seSBzZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIHJlYWRvbmx5IGNvbm5lY3Rpb25zOiBlYzIuQ29ubmVjdGlvbnM7XG4gIHByaXZhdGUgcmVhZG9ubHkgX215c3FsTGlzdGVuZXJQb3J0OiBudW1iZXIgPSAzMzA2O1xuXG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBEYXRhYmFzZVByb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkKTtcbiAgICB0aGlzLnZwYyA9IHByb3BzLnZwYztcbiAgICBsZXQgY29uZmlnO1xuICAgIGlmIChwcm9wcy5hdXJvcmFTZXJ2ZXJsZXNzKSB7XG4gICAgICBjb25maWcgPSB0aGlzLl9jcmVhdGVTZXJ2ZXJsZXNzQ2x1c3Rlcihwcm9wcyk7XG4gICAgfSBlbHNlIGlmIChwcm9wcy5hdXJvcmFTZXJ2ZXJsZXNzVjIpIHtcbiAgICAgIGNvbmZpZyA9IHRoaXMuX2NyZWF0ZVNlcnZlcmxlc3NWMkNsdXN0ZXIocHJvcHMpO1xuICAgIH0gZWxzZSBpZiAocHJvcHMuc2luZ2xlRGJJbnN0YW5jZSkge1xuICAgICAgY29uZmlnID0gdGhpcy5fY3JlYXRlUmRzSW5zdGFuY2UocHJvcHMpO1xuICAgIH0gZWxzZSB7XG4gICAgICBjb25maWcgPSB0aGlzLl9jcmVhdGVSZHNDbHVzdGVyKHByb3BzKTtcbiAgICB9XG4gICAgdGhpcy5zZWNyZXQgPSBjb25maWcuc2VjcmV0O1xuICAgIC8vIGFsbG93IGludGVybmFsbHkgZnJvbSB0aGUgc2FtZSBzZWN1cml0eSBncm91cFxuICAgIGNvbmZpZy5jb25uZWN0aW9ucy5hbGxvd0ludGVybmFsbHkoZWMyLlBvcnQudGNwKHRoaXMuX215c3FsTGlzdGVuZXJQb3J0KSk7XG4gICAgLy8gYWxsb3cgZnJvbSB0aGUgd2hvbGUgdnBjIGNpZHJcbiAgICBjb25maWcuY29ubmVjdGlvbnMuYWxsb3dGcm9tKGVjMi5QZWVyLmlwdjQocHJvcHMudnBjLnZwY0NpZHJCbG9jayksIGVjMi5Qb3J0LnRjcCh0aGlzLl9teXNxbExpc3RlbmVyUG9ydCkpO1xuICAgIHRoaXMuY2x1c3RlckVuZHBvaW50SG9zdG5hbWUgPSBjb25maWcuZW5kcG9pbnQ7XG4gICAgdGhpcy5jbHVzdGVySWRlbnRpZmllciA9IGNvbmZpZy5pZGVudGlmaWVyO1xuICAgIHRoaXMuY29ubmVjdGlvbnMgPSBjb25maWcuY29ubmVjdGlvbnM7XG4gICAgcHJpbnRPdXRwdXQodGhpcywgJ0RCU2VjcmV0QXJuJywgY29uZmlnLnNlY3JldC5zZWNyZXRBcm4pO1xuICAgIHByaW50T3V0cHV0KHRoaXMsICdjbHVzdGVyRW5kcG9pbnRIb3N0bmFtZScsIHRoaXMuY2x1c3RlckVuZHBvaW50SG9zdG5hbWUpO1xuICAgIHByaW50T3V0cHV0KHRoaXMsICdjbHVzdGVySWRlbnRpZmllcicsIHRoaXMuY2x1c3RlcklkZW50aWZpZXIpO1xuICB9XG4gIHByaXZhdGUgX2NyZWF0ZVJkc0luc3RhbmNlKHByb3BzOiBEYXRhYmFzZVByb3BzKTogRGF0YWJhc2VDb25maWcge1xuICAgIGNvbnN0IGRiSW5zdGFuY2UgPSBuZXcgcmRzLkRhdGFiYXNlSW5zdGFuY2UodGhpcywgJ0RCSW5zdGFuY2UnLCB7XG4gICAgICB2cGM6IHByb3BzLnZwYyxcbiAgICAgIGRhdGFiYXNlTmFtZTogJ2tleWNsb2FrJyxcbiAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLmRhdGFiYXNlU3VibmV0cyxcbiAgICAgIGVuZ2luZTogcHJvcHMuaW5zdGFuY2VFbmdpbmUgPz8gcmRzLkRhdGFiYXNlSW5zdGFuY2VFbmdpbmUubXlzcWwoe1xuICAgICAgICB2ZXJzaW9uOiByZHMuTXlzcWxFbmdpbmVWZXJzaW9uLlZFUl84XzBfMjEsXG4gICAgICB9KSxcbiAgICAgIHN0b3JhZ2VFbmNyeXB0ZWQ6IHRydWUsXG4gICAgICBiYWNrdXBSZXRlbnRpb246IHByb3BzLmJhY2t1cFJldGVudGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cyg3KSxcbiAgICAgIGNyZWRlbnRpYWxzOiByZHMuQ3JlZGVudGlhbHMuZnJvbUdlbmVyYXRlZFNlY3JldCgnYWRtaW4nKSxcbiAgICAgIGluc3RhbmNlVHlwZTogcHJvcHMuaW5zdGFuY2VUeXBlID8/IG5ldyBlYzIuSW5zdGFuY2VUeXBlKCdyNS5sYXJnZScpLFxuICAgICAgcGFyYW1ldGVyR3JvdXA6IHJkcy5QYXJhbWV0ZXJHcm91cC5mcm9tUGFyYW1ldGVyR3JvdXBOYW1lKHRoaXMsICdQYXJhbWV0ZXJHcm91cCcsICdkZWZhdWx0Lm15c3FsOC4wJyksXG4gICAgICBkZWxldGlvblByb3RlY3Rpb246IGZhbHNlLFxuICAgICAgcmVtb3ZhbFBvbGljeTogcHJvcHMucmVtb3ZhbFBvbGljeSA/PyBjZGsuUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgfSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGNvbm5lY3Rpb25zOiBkYkluc3RhbmNlLmNvbm5lY3Rpb25zLFxuICAgICAgZW5kcG9pbnQ6IGRiSW5zdGFuY2UuZGJJbnN0YW5jZUVuZHBvaW50QWRkcmVzcyxcbiAgICAgIGlkZW50aWZpZXI6IGRiSW5zdGFuY2UuaW5zdGFuY2VJZGVudGlmaWVyLFxuICAgICAgc2VjcmV0OiBkYkluc3RhbmNlLnNlY3JldCEsXG4gICAgfTtcbiAgfVxuICAvLyBjcmVhdGUgYSBSRFMgZm9yIE15U1FMIERCIGNsdXN0ZXJcbiAgcHJpdmF0ZSBfY3JlYXRlUmRzQ2x1c3Rlcihwcm9wczogRGF0YWJhc2VQcm9wcyk6IERhdGFiYXNlQ29uZmlnIHtcbiAgICBjb25zdCBkYkNsdXN0ZXIgPSBuZXcgcmRzLkRhdGFiYXNlQ2x1c3Rlcih0aGlzLCAnREJDbHVzdGVyJywge1xuICAgICAgZW5naW5lOiBwcm9wcy5jbHVzdGVyRW5naW5lID8/IHJkcy5EYXRhYmFzZUNsdXN0ZXJFbmdpbmUuYXVyb3JhTXlzcWwoe1xuICAgICAgICB2ZXJzaW9uOiByZHMuQXVyb3JhTXlzcWxFbmdpbmVWZXJzaW9uLlZFUl8yXzA5XzEsXG4gICAgICB9KSxcbiAgICAgIGRlZmF1bHREYXRhYmFzZU5hbWU6ICdrZXljbG9haycsXG4gICAgICBkZWxldGlvblByb3RlY3Rpb246IGZhbHNlLFxuICAgICAgY3JlZGVudGlhbHM6IHJkcy5DcmVkZW50aWFscy5mcm9tR2VuZXJhdGVkU2VjcmV0KCdhZG1pbicpLFxuICAgICAgaW5zdGFuY2VQcm9wczoge1xuICAgICAgICB2cGM6IHByb3BzLnZwYyxcbiAgICAgICAgdnBjU3VibmV0czogcHJvcHMuZGF0YWJhc2VTdWJuZXRzLFxuICAgICAgICBpbnN0YW5jZVR5cGU6IHByb3BzLmluc3RhbmNlVHlwZSA/PyBuZXcgZWMyLkluc3RhbmNlVHlwZSgncjUubGFyZ2UnKSxcbiAgICAgIH0sXG4gICAgICBwYXJhbWV0ZXJHcm91cDogcmRzLlBhcmFtZXRlckdyb3VwLmZyb21QYXJhbWV0ZXJHcm91cE5hbWUodGhpcywgJ1BhcmFtZXRlckdyb3VwJywgJ2RlZmF1bHQuYXVyb3JhLW15c3FsOC4wJyksXG4gICAgICBiYWNrdXA6IHtcbiAgICAgICAgcmV0ZW50aW9uOiBwcm9wcy5iYWNrdXBSZXRlbnRpb24gPz8gY2RrLkR1cmF0aW9uLmRheXMoNyksXG4gICAgICB9LFxuICAgICAgc3RvcmFnZUVuY3J5cHRlZDogdHJ1ZSxcbiAgICAgIHJlbW92YWxQb2xpY3k6IHByb3BzLnJlbW92YWxQb2xpY3kgPz8gY2RrLlJlbW92YWxQb2xpY3kuUkVUQUlOLFxuICAgIH0pO1xuICAgIHJldHVybiB7XG4gICAgICBjb25uZWN0aW9uczogZGJDbHVzdGVyLmNvbm5lY3Rpb25zLFxuICAgICAgZW5kcG9pbnQ6IGRiQ2x1c3Rlci5jbHVzdGVyRW5kcG9pbnQuaG9zdG5hbWUsXG4gICAgICBpZGVudGlmaWVyOiBkYkNsdXN0ZXIuY2x1c3RlcklkZW50aWZpZXIsXG4gICAgICBzZWNyZXQ6IGRiQ2x1c3Rlci5zZWNyZXQhLFxuICAgIH07XG4gIH1cbiAgcHJpdmF0ZSBfY3JlYXRlU2VydmVybGVzc0NsdXN0ZXIocHJvcHM6IERhdGFiYXNlUHJvcHMpOiBEYXRhYmFzZUNvbmZpZyB7XG4gICAgY29uc3QgZGJDbHVzdGVyID0gbmV3IHJkcy5TZXJ2ZXJsZXNzQ2x1c3Rlcih0aGlzLCAnQXVyb3JhU2VydmVybGVzc0NsdXN0ZXInLCB7XG4gICAgICBlbmdpbmU6IHJkcy5EYXRhYmFzZUNsdXN0ZXJFbmdpbmUuQVVST1JBX01ZU1FMLFxuICAgICAgdnBjOiBwcm9wcy52cGMsXG4gICAgICBkZWZhdWx0RGF0YWJhc2VOYW1lOiAna2V5Y2xvYWsnLFxuICAgICAgdnBjU3VibmV0czogcHJvcHMuZGF0YWJhc2VTdWJuZXRzLFxuICAgICAgY3JlZGVudGlhbHM6IHJkcy5DcmVkZW50aWFscy5mcm9tR2VuZXJhdGVkU2VjcmV0KCdhZG1pbicpLFxuICAgICAgYmFja3VwUmV0ZW50aW9uOiBwcm9wcy5iYWNrdXBSZXRlbnRpb24gPz8gY2RrLkR1cmF0aW9uLmRheXMoNyksXG4gICAgICBkZWxldGlvblByb3RlY3Rpb246IGZhbHNlLFxuICAgICAgcmVtb3ZhbFBvbGljeTogcHJvcHMucmVtb3ZhbFBvbGljeSA/PyBjZGsuUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgICBwYXJhbWV0ZXJHcm91cDogcmRzLlBhcmFtZXRlckdyb3VwLmZyb21QYXJhbWV0ZXJHcm91cE5hbWUodGhpcywgJ1BhcmFtZXRlckdyb3VwJywgJ2RlZmF1bHQuYXVyb3JhLW15c3FsOC4wJyksXG4gICAgfSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGNvbm5lY3Rpb25zOiBkYkNsdXN0ZXIuY29ubmVjdGlvbnMsXG4gICAgICBlbmRwb2ludDogZGJDbHVzdGVyLmNsdXN0ZXJFbmRwb2ludC5ob3N0bmFtZSxcbiAgICAgIGlkZW50aWZpZXI6IGRiQ2x1c3Rlci5jbHVzdGVySWRlbnRpZmllcixcbiAgICAgIHNlY3JldDogZGJDbHVzdGVyLnNlY3JldCEsXG4gICAgfTtcbiAgfVxuICAvLyBjcmVhdGUgYSBSRFMgZm9yIE15U1FMIERCIGNsdXN0ZXIgd2l0aCBBdXJvcmEgU2VydmVybGVzcyB2MlxuICBwcml2YXRlIF9jcmVhdGVTZXJ2ZXJsZXNzVjJDbHVzdGVyKHByb3BzOiBEYXRhYmFzZVByb3BzKTogRGF0YWJhc2VDb25maWcge1xuICAgIGNvbnN0IGRiQ2x1c3RlciA9IG5ldyByZHMuRGF0YWJhc2VDbHVzdGVyKHRoaXMsICdEQkNsdXN0ZXInLCB7XG4gICAgICBlbmdpbmU6IHByb3BzLmNsdXN0ZXJFbmdpbmUgPz8gcmRzLkRhdGFiYXNlQ2x1c3RlckVuZ2luZS5hdXJvcmFNeXNxbCh7XG4gICAgICAgIHZlcnNpb246IHJkcy5BdXJvcmFNeXNxbEVuZ2luZVZlcnNpb24uVkVSXzNfMDJfMCxcbiAgICAgIH0pLFxuICAgICAgZGVmYXVsdERhdGFiYXNlTmFtZTogJ2tleWNsb2FrJyxcbiAgICAgIGRlbGV0aW9uUHJvdGVjdGlvbjogZmFsc2UsXG4gICAgICBjcmVkZW50aWFsczogcmRzLkNyZWRlbnRpYWxzLmZyb21HZW5lcmF0ZWRTZWNyZXQoJ2FkbWluJyksXG4gICAgICBpbnN0YW5jZVByb3BzOiB7XG4gICAgICAgIHZwYzogcHJvcHMudnBjLFxuICAgICAgICB2cGNTdWJuZXRzOiBwcm9wcy5kYXRhYmFzZVN1Ym5ldHMsXG4gICAgICAgIC8vIFNwZWNpZnkgc2VydmVybGVzcyBJbnN0YW5jZSBUeXBlXG4gICAgICAgIGluc3RhbmNlVHlwZTogbmV3IGVjMi5JbnN0YW5jZVR5cGUoJ3NlcnZlcmxlc3MnKSxcbiAgICAgIH0sXG4gICAgICAvLyBTZXQgZGVmYXVsdCBwYXJhbWV0ZXIgZ3JvdXAgZm9yIEF1cm9yYSBNeVNRTCA4LjBcbiAgICAgIHBhcmFtZXRlckdyb3VwOiByZHMuUGFyYW1ldGVyR3JvdXAuZnJvbVBhcmFtZXRlckdyb3VwTmFtZSh0aGlzLCAnUGFyYW1ldGVyR3JvdXAnLCAnZGVmYXVsdC5hdXJvcmEtbXlzcWw4LjAnKSxcbiAgICAgIGJhY2t1cDoge1xuICAgICAgICByZXRlbnRpb246IHByb3BzLmJhY2t1cFJldGVudGlvbiA/PyBjZGsuRHVyYXRpb24uZGF5cyg3KSxcbiAgICAgIH0sXG4gICAgICBzdG9yYWdlRW5jcnlwdGVkOiB0cnVlLFxuICAgICAgcmVtb3ZhbFBvbGljeTogcHJvcHMucmVtb3ZhbFBvbGljeSA/PyBjZGsuUmVtb3ZhbFBvbGljeS5SRVRBSU4sXG4gICAgfSk7XG4gICAgLy8gU2V0IFNlcnZlcmxlc3MgVjIgU2NhbGluZyBDb25maWd1cmF0aW9uXG4gICAgLy8gVE9ETzogVXNlIGNsZWFuZXIgd2F5IHRvIHNldCBzY2FsaW5nIGNvbmZpZ3VyYXRpb24uXG4gICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2F3cy9hd3MtY2RrL2lzc3Vlcy8yMDE5N1xuICAgIChcbiAgICAgIGRiQ2x1c3Rlci5ub2RlLmZpbmRDaGlsZCgnUmVzb3VyY2UnKSBhcyByZHMuQ2ZuREJDbHVzdGVyXG4gICAgKS5zZXJ2ZXJsZXNzVjJTY2FsaW5nQ29uZmlndXJhdGlvbiA9IHtcbiAgICAgIG1pbkNhcGFjaXR5OiBwcm9wcy5taW5DYXBhY2l0eSA/PyAwLjUsXG4gICAgICBtYXhDYXBhY2l0eTogcHJvcHMubWF4Q2FwYWNpdHkgPz8gMTAsXG4gICAgfTtcbiAgICByZXR1cm4ge1xuICAgICAgY29ubmVjdGlvbnM6IGRiQ2x1c3Rlci5jb25uZWN0aW9ucyxcbiAgICAgIGVuZHBvaW50OiBkYkNsdXN0ZXIuY2x1c3RlckVuZHBvaW50Lmhvc3RuYW1lLFxuICAgICAgaWRlbnRpZmllcjogZGJDbHVzdGVyLmNsdXN0ZXJJZGVudGlmaWVyLFxuICAgICAgc2VjcmV0OiBkYkNsdXN0ZXIuc2VjcmV0ISxcbiAgICB9O1xuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ29udGFpbmVyU2VydmljZVByb3BzIHtcbiAgLyoqXG4gICAqIFRoZSBlbnZpcm9ubWVudCB2YXJpYWJsZXMgdG8gcGFzcyB0byB0aGUga2V5Y2xvYWsgY29udGFpbmVyXG4gICAqL1xuICByZWFkb25seSBlbnY/OiB7IFtrZXk6IHN0cmluZ106IHN0cmluZyB9O1xuICAvKipcbiAgICogS2V5Y2xvYWsgdmVyc2lvbiBmb3IgdGhlIGNvbnRhaW5lciBpbWFnZVxuICAgKi9cbiAgcmVhZG9ubHkga2V5Y2xvYWtWZXJzaW9uOiBLZXljbG9ha1ZlcnNpb247XG4gIC8qKlxuICAgKiBUaGUgVlBDIGZvciB0aGUgc2VydmljZVxuICAgKi9cbiAgcmVhZG9ubHkgdnBjOiBlYzIuSVZwYztcbiAgLyoqXG4gICAqIFZQQyBzdWJuZXRzIGZvciBrZXljbG9hayBzZXJ2aWNlXG4gICAqL1xuICByZWFkb25seSBwcml2YXRlU3VibmV0cz86IGVjMi5TdWJuZXRTZWxlY3Rpb247XG4gIC8qKlxuICAgKiBWUEMgcHVibGljIHN1Ym5ldHMgZm9yIEFMQlxuICAgKi9cbiAgcmVhZG9ubHkgcHVibGljU3VibmV0cz86IGVjMi5TdWJuZXRTZWxlY3Rpb247XG4gIC8qKlxuICAgKiBUaGUgUkRTIGRhdGFiYXNlIGZvciB0aGUgc2VydmljZVxuICAgKi9cbiAgcmVhZG9ubHkgZGF0YWJhc2U6IERhdGFiYXNlO1xuICAvKipcbiAgICogVGhlIHNlY3JldHMgbWFuYWdlciBzZWNyZXQgZm9yIHRoZSBrZXljbG9ha1xuICAgKi9cbiAgcmVhZG9ubHkga2V5Y2xvYWtTZWNyZXQ6IHNlY3JldHNtYW5hZ2VyLklTZWNyZXQ7XG4gIC8qKlxuICAgKiBUaGUgQUNNIGNlcnRpZmljYXRlXG4gICAqL1xuICByZWFkb25seSBjZXJ0aWZpY2F0ZTogY2VydG1nci5JQ2VydGlmaWNhdGU7XG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIGNyZWF0ZSB0aGUgYmFzdGlvbiBob3N0XG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBiYXN0aW9uPzogYm9vbGVhbjtcbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gZW5hYmxlIHRoZSBFQ1Mgc2VydmljZSBkZXBsb3ltZW50IGNpcmN1aXQgYnJlYWtlclxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgY2lyY3VpdEJyZWFrZXI/OiBib29sZWFuO1xuICAvKipcbiAgICogTnVtYmVyIG9mIGtleWNsb2FrIG5vZGUgaW4gdGhlIGNsdXN0ZXJcbiAgICpcbiAgICogQGRlZmF1bHQgMVxuICAgKi9cbiAgcmVhZG9ubHkgbm9kZUNvdW50PzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIHN0aWNreSBzZXNzaW9uIGR1cmF0aW9uIGZvciB0aGUga2V5Y2xvYWsgd29ya2xvYWQgd2l0aCBBTEIuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gb25lIGRheVxuICAgKi9cbiAgcmVhZG9ubHkgc3RpY2tpbmVzc0Nvb2tpZUR1cmF0aW9uPzogY2RrLkR1cmF0aW9uO1xuXG4gIC8qKlxuICAgKiBBdXRvc2NhbGluZyBmb3IgdGhlIEVDUyBTZXJ2aWNlXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gbm8gZWNzIHNlcnZpY2UgYXV0b3NjYWxpbmdcbiAgICovXG4gIHJlYWRvbmx5IGF1dG9TY2FsZVRhc2s/OiBBdXRvU2NhbGVUYXNrO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHB1dCB0aGUgcHV0IHRoZSBsb2FkIGJhbGFuY2VyIGluIHRoZSBwdWJsaWMgb3IgcHJpdmF0ZSBzdWJuZXRzXG4gICAqXG4gICAqIEBkZWZhdWx0IHRydWVcbiAgICovXG4gIHJlYWRvbmx5IGludGVybmV0RmFjaW5nPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogVGhlIGhvc3RuYW1lIHRvIHVzZSBmb3IgdGhlIGtleWNsb2FrIHNlcnZlclxuICAgKi9cbiAgcmVhZG9ubHkgaG9zdG5hbWU/OiBzdHJpbmc7XG5cblxuICAvKipcbiAgICogT3ZlcnJpZGVzIHRoZSBkZWZhdWx0IGltYWdlXG4gICAqXG4gICAqIEBkZWZhdWx0IHF1YXkuaW8va2V5Y2xvYWsva2V5Y2xvYWs6JHtLRVlDTE9BS19WRVJTSU9OfVxuICAgKi9cbiAgcmVhZG9ubHkgY29udGFpbmVySW1hZ2U/OiBlY3MuQ29udGFpbmVySW1hZ2U7XG59XG5cbmV4cG9ydCBjbGFzcyBDb250YWluZXJTZXJ2aWNlIGV4dGVuZHMgQ29uc3RydWN0IHtcbiAgcmVhZG9ubHkgc2VydmljZTogZWNzLkZhcmdhdGVTZXJ2aWNlO1xuICByZWFkb25seSBhcHBsaWNhdGlvbkxvYWRCYWxhbmNlcjogZWxidjIuQXBwbGljYXRpb25Mb2FkQmFsYW5jZXI7XG4gIC8vIHJlYWRvbmx5IG5ldHdvcmtMb2FkQmFsYW5jZXI6IGVsYnYyLk5ldHdvcmtMb2FkQmFsYW5jZXI7XG4gIHJlYWRvbmx5IGtleWNsb2FrVXNlclNlY3JldDogc2VjcmV0c21hbmFnZXIuSVNlY3JldDtcbiAgY29uc3RydWN0b3Ioc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgcHJvcHM6IENvbnRhaW5lclNlcnZpY2VQcm9wcykge1xuICAgIHN1cGVyKHNjb3BlLCBpZCk7XG5cbiAgICBjb25zdCByZWdpb24gPSBjZGsuU3RhY2sub2YodGhpcykucmVnaW9uO1xuICAgIGNvbnN0IGNvbnRhaW5lclBvcnQgPSA4MDgwO1xuICAgIGNvbnN0IGNvbm5lY3Rpb25TdHJpbmcgPSBgamRiYzpteXNxbDovLyR7cHJvcHMuZGF0YWJhc2UuY2x1c3RlckVuZHBvaW50SG9zdG5hbWV9OjMzMDYva2V5Y2xvYWtgO1xuICAgIC8vIGNvbnN0IHByb3RvY29sID0gZWxidjIuQXBwbGljYXRpb25Qcm90b2NvbC5IVFRQO1xuICAgIGNvbnN0IGVudHJ5UG9pbnQgPSBbJy9vcHQva2V5Y2xvYWsvYmluL2tjLnNoJywgJ3N0YXJ0JywgJy0tb3B0aW1pemVkJ107XG4gICAgY29uc3QgczNQaW5nQnVja2V0ID0gbmV3IHMzLkJ1Y2tldCh0aGlzLCAna2V5Y2xvYWtfczNfcGluZycpO1xuICAgIGNvbnN0IGltYWdlID0gcHJvcHMuY29udGFpbmVySW1hZ2UgPz8gZWNzLkNvbnRhaW5lckltYWdlLmZyb21SZWdpc3RyeSh0aGlzLmdldEtleUNsb2FrRG9ja2VySW1hZ2VVcmkocHJvcHMua2V5Y2xvYWtWZXJzaW9uLnZlcnNpb24pKTtcbiAgICBjb25zdCBzZWNyZXRzOiB7W2tleTogc3RyaW5nXTogY2RrLmF3c19lY3MuU2VjcmV0fSA9IHtcbiAgICAgIEtDX0RCX1BBU1NXT1JEOiBlY3MuU2VjcmV0LmZyb21TZWNyZXRzTWFuYWdlcihwcm9wcy5kYXRhYmFzZS5zZWNyZXQsICdwYXNzd29yZCcpLFxuICAgICAgS0VZQ0xPQUtfQURNSU46IGVjcy5TZWNyZXQuZnJvbVNlY3JldHNNYW5hZ2VyKHByb3BzLmtleWNsb2FrU2VjcmV0LCAndXNlcm5hbWUnKSxcbiAgICAgIEtFWUNMT0FLX0FETUlOX1BBU1NXT1JEOiBlY3MuU2VjcmV0LmZyb21TZWNyZXRzTWFuYWdlcihwcm9wcy5rZXljbG9ha1NlY3JldCwgJ3Bhc3N3b3JkJyksXG4gICAgfTtcbiAgICBjb25zdCBwb3J0TWFwcGluZ3M6IGVjcy5Qb3J0TWFwcGluZ1tdID0gW1xuICAgICAgeyBjb250YWluZXJQb3J0OiBjb250YWluZXJQb3J0IH0sIC8vIHdlYiBwb3J0XG4gICAgICB7IGNvbnRhaW5lclBvcnQ6IDc4MDAgfSwgLy8gamdyb3Vwcy1zM1xuICAgICAgeyBjb250YWluZXJQb3J0OiA1NzgwMCB9LCAvLyBqZ3JvdXBzLXMzLWZkXG4gICAgXTtcbiAgICBjb25zdCB2cGMgPSBwcm9wcy52cGM7XG4gICAgY29uc3QgY2x1c3RlciA9IG5ldyBlY3MuQ2x1c3Rlcih0aGlzLCAnQ2x1c3RlcicsIHsgdnBjLCBjb250YWluZXJJbnNpZ2h0czogdHJ1ZSB9KTtcbiAgICBjbHVzdGVyLm5vZGUuYWRkRGVwZW5kZW5jeShwcm9wcy5kYXRhYmFzZSk7XG4gICAgY29uc3QgZXhlY3V0aW9uUm9sZSA9IG5ldyBpYW0uUm9sZSh0aGlzLCAnVGFza1JvbGUnLCB7XG4gICAgICBhc3N1bWVkQnk6IG5ldyBpYW0uQ29tcG9zaXRlUHJpbmNpcGFsKFxuICAgICAgICBuZXcgaWFtLlNlcnZpY2VQcmluY2lwYWwoJ2Vjcy5hbWF6b25hd3MuY29tJyksXG4gICAgICAgIG5ldyBpYW0uU2VydmljZVByaW5jaXBhbCgnZWNzLXRhc2tzLmFtYXpvbmF3cy5jb20nKSxcbiAgICAgICksXG4gICAgfSk7XG4gICAgY29uc3QgdGFza0RlZmluaXRpb24gPSBuZXcgZWNzLkZhcmdhdGVUYXNrRGVmaW5pdGlvbih0aGlzLCAnVGFza0RlZicsIHtcbiAgICAgIGNwdTogMjA0OCxcbiAgICAgIG1lbW9yeUxpbWl0TWlCOiA0MDk2LFxuICAgICAgZXhlY3V0aW9uUm9sZSxcbiAgICB9KTtcblxuICAgIGNvbnN0IGxvZ0dyb3VwID0gbmV3IGxvZ3MuTG9nR3JvdXAodGhpcywgJ0xvZ0dyb3VwJywge1xuICAgICAgcmV0ZW50aW9uOiBsb2dzLlJldGVudGlvbkRheXMuT05FX01PTlRILFxuICAgICAgcmVtb3ZhbFBvbGljeTogY2RrLlJlbW92YWxQb2xpY3kuUkVUQUlOLFxuICAgIH0pO1xuXG4gICAgY29uc3QgczNVc2VyID0gbmV3IGlhbS5Vc2VyKHRoaXMsICdTM0tleWNsb2FrVXNlcicpO1xuICAgIGNvbnN0IGFjY2Vzc0tleSA9IG5ldyBpYW0uQWNjZXNzS2V5KHRoaXMsICdTM0tleWNsb2FrVXNlckFjY2Vzc0tleScsIHsgdXNlcjogczNVc2VyIH0pO1xuICAgIHRoaXMua2V5Y2xvYWtVc2VyU2VjcmV0ID0gbmV3IHNlY3JldHNtYW5hZ2VyLlNlY3JldCh0aGlzLCAnUzNLZXljbG9ha1VzZXJTZWNyZXQnLCB7XG4gICAgICBzZWNyZXRTdHJpbmdWYWx1ZTogYWNjZXNzS2V5LnNlY3JldEFjY2Vzc0tleSxcbiAgICB9KTtcbiAgICBzM1BpbmdCdWNrZXQhLmdyYW50UmVhZFdyaXRlKHMzVXNlcik7XG5cbiAgICBjb25zdCBlbnZpcm9ubWVudDoge1trZXk6IHN0cmluZ106IHN0cmluZ30gPSB7XG4gICAgICBKQVZBX09QVFNfQVBQRU5EOiBgXG4gICAgICAtRGpncm91cHMuczMucmVnaW9uX25hbWU9JHtyZWdpb259XG4gICAgICAtRGpncm91cHMuczMuYnVja2V0X25hbWU9JHtzM1BpbmdCdWNrZXQhLmJ1Y2tldE5hbWV9XG4gICAgICAtRGpncm91cHMuczMuYWNjZXNzX2tleT0ke2FjY2Vzc0tleS5hY2Nlc3NLZXlJZH1cbiAgICAgIC1Eamdyb3Vwcy5zMy5zZWNyZXRfYWNjZXNzX2tleT0ke2FjY2Vzc0tleS5zZWNyZXRBY2Nlc3NLZXl9XG4gICAgICBgLnJlcGxhY2UoJ1xcclxcbicsICcnKS5yZXBsYWNlKCdcXG4nLCAnJykucmVwbGFjZSgvXFxzKy9nLCAnICcpLFxuICAgICAgLy8gV2UgaGF2ZSBzZWxlY3RlZCB0aGUgY2FjaGUgc3RhY2sgb2YgJ2VjMicgd2hpY2ggdXNlcyBTM19QSU5HIHVuZGVyIHRoZSBob29kXG4gICAgICAvLyBUaGlzIGlzIHRoZSBBV1MgbmF0aXZlIGNsdXN0ZXIgZGlzY292ZXJ5IGFwcHJvYWNoIGZvciBjYWNoaW5nXG4gICAgICAvLyBTZWU6IGh0dHBzOi8vd3d3LmtleWNsb2FrLm9yZy9zZXJ2ZXIvY2FjaGluZyNfdHJhbnNwb3J0X3N0YWNrc1xuICAgICAgS0NfQ0FDSEVfU1RBQ0s6ICdlYzInLFxuICAgICAgS0NfREI6ICdteXNxbCcsXG4gICAgICBLQ19EQl9VUkxfREFUQUJBU0U6ICdrZXljbG9haycsXG4gICAgICBLQ19EQl9VUkw6IGNvbm5lY3Rpb25TdHJpbmcsXG4gICAgICBLQ19EQl9VUkxfUE9SVDogJzMzMDYnLFxuICAgICAgS0NfREJfVVNFUk5BTUU6ICdhZG1pbicsXG4gICAgICBLQ19IT1NUTkFNRTogcHJvcHMuaG9zdG5hbWUhLFxuICAgICAgS0NfSE9TVE5BTUVfU1RSSUNUX0JBQ0tDSEFOTkVMOiAndHJ1ZScsXG4gICAgICBLQ19QUk9YWTogJ2VkZ2UnLFxuICAgICAgS0NfSEVBTFRIX0VOQUJMRUQ6ICd0cnVlJyxcbiAgICB9O1xuXG4gICAgY29uc3Qga2MgPSB0YXNrRGVmaW5pdGlvbi5hZGRDb250YWluZXIoJ2tleWNsb2FrJywge1xuICAgICAgaW1hZ2UsXG4gICAgICBlbnRyeVBvaW50LFxuICAgICAgZW52aXJvbm1lbnQ6IE9iamVjdC5hc3NpZ24oZW52aXJvbm1lbnQsIHByb3BzLmVudiksXG4gICAgICBzZWNyZXRzLFxuICAgICAgbG9nZ2luZzogZWNzLkxvZ0RyaXZlcnMuYXdzTG9ncyh7XG4gICAgICAgIHN0cmVhbVByZWZpeDogJ2tleWNsb2FrJyxcbiAgICAgICAgbG9nR3JvdXAsXG4gICAgICB9KSxcbiAgICB9KTtcbiAgICBrYy5hZGRQb3J0TWFwcGluZ3MoLi4ucG9ydE1hcHBpbmdzKTtcblxuICAgIC8vIHdlIG5lZWQgZXh0cmEgcHJpdmlsZWdlcyB0byBmZXRjaCBrZXljbG9hayBkb2NrZXIgaW1hZ2VzIGZyb20gQ2hpbmEgbWlycm9yIHNpdGVcbiAgICB0YXNrRGVmaW5pdGlvbi5leGVjdXRpb25Sb2xlPy5hZGRNYW5hZ2VkUG9saWN5KGlhbS5NYW5hZ2VkUG9saWN5LmZyb21Bd3NNYW5hZ2VkUG9saWN5TmFtZSgnQW1hem9uRUMyQ29udGFpbmVyUmVnaXN0cnlSZWFkT25seScpKTtcblxuICAgIHRoaXMuc2VydmljZSA9IG5ldyBlY3MuRmFyZ2F0ZVNlcnZpY2UodGhpcywgJ1NlcnZpY2UnLCB7XG4gICAgICBjbHVzdGVyLFxuICAgICAgdGFza0RlZmluaXRpb24sXG4gICAgICBjaXJjdWl0QnJlYWtlcjogcHJvcHMuY2lyY3VpdEJyZWFrZXIgPyB7IHJvbGxiYWNrOiB0cnVlIH0gOiB1bmRlZmluZWQsXG4gICAgICBkZXNpcmVkQ291bnQ6IHByb3BzLm5vZGVDb3VudCA/PyAyLFxuICAgICAgaGVhbHRoQ2hlY2tHcmFjZVBlcmlvZDogY2RrLkR1cmF0aW9uLnNlY29uZHMoMTIwKSxcbiAgICB9KTtcblxuICAgIHRoaXMuc2VydmljZS5jb25uZWN0aW9ucy5hbGxvd0Zyb20odGhpcy5zZXJ2aWNlLmNvbm5lY3Rpb25zLCBlYzIuUG9ydC50Y3AoNzgwMCksICdrYyBqZ3JvdXBzLXRjcCcpO1xuICAgIHRoaXMuc2VydmljZS5jb25uZWN0aW9ucy5hbGxvd0Zyb20odGhpcy5zZXJ2aWNlLmNvbm5lY3Rpb25zLCBlYzIuUG9ydC50Y3AoNTc4MDApLCAna2Mgamdyb3Vwcy10Y3AtZmQnKTtcbiAgICBzM1BpbmdCdWNrZXQhLmdyYW50UmVhZFdyaXRlKHRhc2tEZWZpbml0aW9uLnRhc2tSb2xlKTtcblxuICAgIGlmIChwcm9wcy5hdXRvU2NhbGVUYXNrKSB7XG4gICAgICBjb25zdCBtaW5DYXBhY2l0eSA9IHByb3BzLmF1dG9TY2FsZVRhc2subWluID8/IHByb3BzLm5vZGVDb3VudCA/PyAyO1xuICAgICAgY29uc3Qgc2NhbGluZyA9IHRoaXMuc2VydmljZS5hdXRvU2NhbGVUYXNrQ291bnQoe1xuICAgICAgICBtaW5DYXBhY2l0eSxcbiAgICAgICAgbWF4Q2FwYWNpdHk6IHByb3BzLmF1dG9TY2FsZVRhc2subWF4ID8/IG1pbkNhcGFjaXR5ICsgNSxcbiAgICAgIH0pO1xuICAgICAgc2NhbGluZy5zY2FsZU9uQ3B1VXRpbGl6YXRpb24oJ0NwdVNjYWxpbmcnLCB7XG4gICAgICAgIHRhcmdldFV0aWxpemF0aW9uUGVyY2VudDogcHJvcHMuYXV0b1NjYWxlVGFzay50YXJnZXRDcHVVdGlsaXphdGlvbiA/PyA3NSxcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICAvLyBsaXN0ZW5lciBwcm90b2NvbCAnVExTJyBpcyBub3Qgc3VwcG9ydGVkIHdpdGggYSB0YXJnZXQgZ3JvdXAgd2l0aCB0aGUgdGFyZ2V0LXR5cGUgJ0FMQidcblxuICAgIHRoaXMuYXBwbGljYXRpb25Mb2FkQmFsYW5jZXIgPSBuZXcgZWxidjIuQXBwbGljYXRpb25Mb2FkQmFsYW5jZXIodGhpcywgJ0FMQicsIHtcbiAgICAgIHZwYyxcbiAgICAgIHZwY1N1Ym5ldHM6IHByb3BzLnB1YmxpY1N1Ym5ldHMsXG4gICAgICBpbnRlcm5ldEZhY2luZzogdHJ1ZSxcbiAgICAgIC8vIHZwY1N1Ym5ldHM6IHByb3BzLmludGVybmV0RmFjaW5nID8gcHJvcHMucHVibGljU3VibmV0cyA6IHByb3BzLnByaXZhdGVTdWJuZXRzLFxuICAgICAgLy8gaW50ZXJuZXRGYWNpbmc6IHByb3BzLmludGVybmV0RmFjaW5nLFxuICAgIH0pO1xuICAgIHByaW50T3V0cHV0KHRoaXMsICdFbmRwb2ludFVSTCcsIGBodHRwczovLyR7dGhpcy5hcHBsaWNhdGlvbkxvYWRCYWxhbmNlci5sb2FkQmFsYW5jZXJEbnNOYW1lfWApO1xuXG4gICAgY29uc3QgbGlzdGVuZXIgPSB0aGlzLmFwcGxpY2F0aW9uTG9hZEJhbGFuY2VyLmFkZExpc3RlbmVyKCdBTEJfSHR0cHNMaXN0ZW5lcicsIHtcbiAgICAgIHByb3RvY29sOiBlbGJ2Mi5BcHBsaWNhdGlvblByb3RvY29sLkhUVFBTLFxuICAgICAgY2VydGlmaWNhdGVzOiBbeyBjZXJ0aWZpY2F0ZUFybjogcHJvcHMuY2VydGlmaWNhdGUuY2VydGlmaWNhdGVBcm4gfV0sXG4gICAgfSk7XG4gICAgLy8gXCJJZiB0aGUgdGFyZ2V0IHR5cGUgaXMgQUxCLCB0aGUgdGFyZ2V0IG11c3QgaGF2ZSBhdCBsZWFzdCBvbmUgbGlzdGVuZXIgdGhhdCBtYXRjaGVzIHRoZSB0YXJnZXQgZ3JvdXAgcG9ydCBvciBhbnkgc3BlY2lmaWVkIHBvcnQgb3ZlcnJpZGVzXG4gICAgbGlzdGVuZXIuYWRkVGFyZ2V0cygnRUNTVGFyZ2V0Jywge1xuICAgICAgcHJvdG9jb2w6IGVsYnYyLkFwcGxpY2F0aW9uUHJvdG9jb2wuSFRUUCxcbiAgICAgIHNsb3dTdGFydDogY2RrLkR1cmF0aW9uLnNlY29uZHMoNjApLFxuICAgICAgc3RpY2tpbmVzc0Nvb2tpZUR1cmF0aW9uOiBwcm9wcy5zdGlja2luZXNzQ29va2llRHVyYXRpb24gPz8gY2RrLkR1cmF0aW9uLmRheXMoMSksXG4gICAgICB0YXJnZXRzOiBbdGhpcy5zZXJ2aWNlXSxcbiAgICAgIGhlYWx0aENoZWNrOiB7XG4gICAgICAgIGhlYWx0aHlUaHJlc2hvbGRDb3VudDogMyxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICAvLyBhbGxvdyB0YXNrIGV4ZWN1dGlvbiByb2xlIHRvIHJlYWQgdGhlIHNlY3JldHNcbiAgICBwcm9wcy5kYXRhYmFzZS5zZWNyZXQuZ3JhbnRSZWFkKHRhc2tEZWZpbml0aW9uLmV4ZWN1dGlvblJvbGUhKTtcbiAgICBwcm9wcy5rZXljbG9ha1NlY3JldC5ncmFudFJlYWQodGFza0RlZmluaXRpb24uZXhlY3V0aW9uUm9sZSEpO1xuXG4gICAgLy8gYWxsb3cgZWNzIHRhc2sgY29ubmVjdCB0byBkYXRhYmFzZVxuICAgIHByb3BzLmRhdGFiYXNlLmNvbm5lY3Rpb25zLmFsbG93RGVmYXVsdFBvcnRGcm9tKHRoaXMuc2VydmljZSk7XG5cblxuICAgIC8vIGNyZWF0ZSBhIGJhc3Rpb24gaG9zdFxuICAgIGlmIChwcm9wcy5iYXN0aW9uID09PSB0cnVlKSB7XG4gICAgICBjb25zdCBiYXN0ID0gbmV3IGVjMi5CYXN0aW9uSG9zdExpbnV4KHRoaXMsICdCYXN0Jywge1xuICAgICAgICB2cGMsXG4gICAgICAgIGluc3RhbmNlVHlwZTogbmV3IGVjMi5JbnN0YW5jZVR5cGUoJ3QzLnNtYWxsJyksXG4gICAgICB9KTtcbiAgICAgIHByb3BzLmRhdGFiYXNlLmNvbm5lY3Rpb25zLmFsbG93RGVmYXVsdFBvcnRGcm9tKGJhc3QpO1xuICAgIH1cbiAgfVxuICBwcml2YXRlIGdldEltYWdlVXJpRnJvbU1hcChtYXA6IGRvY2tlckltYWdlTWFwLCB2ZXJzaW9uOiBzdHJpbmcsIGlkOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIGNvbnN0IHN0YWNrID0gY2RrLlN0YWNrLm9mKHRoaXMpO1xuICAgIGlmIChjZGsuVG9rZW4uaXNVbnJlc29sdmVkKHN0YWNrLnJlZ2lvbikpIHtcbiAgICAgIGNvbnN0IG1hcHBpbmc6IHsgW2sxOiBzdHJpbmddOiB7IFtrMjogc3RyaW5nXTogYW55IH0gfSA9IHt9O1xuICAgICAgZm9yIChsZXQgW3BhcnRpdGlvbiwgdXJpXSBvZiBPYmplY3QuZW50cmllcyhtYXApKSB7XG4gICAgICAgIHVyaSArPSB2ZXJzaW9uO1xuICAgICAgICBtYXBwaW5nW3BhcnRpdGlvbl0gPSB7IHVyaSB9O1xuICAgICAgfVxuICAgICAgY29uc3QgaW1hZ2VNYXAgPSBuZXcgY2RrLkNmbk1hcHBpbmcodGhpcywgaWQsIHsgbWFwcGluZyB9KTtcbiAgICAgIHJldHVybiBpbWFnZU1hcC5maW5kSW5NYXAoY2RrLkF3cy5QQVJUSVRJT04sICd1cmknKTtcbiAgICB9IGVsc2Uge1xuICAgICAgaWYgKHN0YWNrLnJlZ2lvbi5zdGFydHNXaXRoKCdjbi0nKSkge1xuICAgICAgICByZXR1cm4gbWFwWydhd3MtY24nXSArPSB2ZXJzaW9uO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIG1hcC5hd3MgKz0gdmVyc2lvbjtcbiAgICAgIH1cbiAgICB9XG4gIH1cbiAgcHJpdmF0ZSBnZXRLZXlDbG9ha0RvY2tlckltYWdlVXJpKHZlcnNpb246IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIHRoaXMuZ2V0SW1hZ2VVcmlGcm9tTWFwKEtFWUNMT0FLX0RPQ0tFUl9JTUFHRV9VUklfTUFQLCB2ZXJzaW9uLCAnS2V5Y2xvYWtJbWFnZU1hcCcpO1xuICB9XG59XG5cbi8qKlxuICogQ3JlYXRlIG9yIGltcG9ydCBWUENcbiAqIEBwYXJhbSBzY29wZSB0aGUgY2RrIHNjb3BlXG4gKi9cbmZ1bmN0aW9uIGdldE9yQ3JlYXRlVnBjKHNjb3BlOiBDb25zdHJ1Y3QpOiBlYzIuSVZwYyB7XG4gIC8vIHVzZSBhbiBleGlzdGluZyB2cGMgb3IgY3JlYXRlIGEgbmV3IG9uZVxuICByZXR1cm4gc2NvcGUubm9kZS50cnlHZXRDb250ZXh0KCd1c2VfZGVmYXVsdF92cGMnKSA9PT0gJzEnID9cbiAgICBlYzIuVnBjLmZyb21Mb29rdXAoc2NvcGUsICdWcGMnLCB7IGlzRGVmYXVsdDogdHJ1ZSB9KSA6XG4gICAgc2NvcGUubm9kZS50cnlHZXRDb250ZXh0KCd1c2VfdnBjX2lkJykgP1xuICAgICAgZWMyLlZwYy5mcm9tTG9va3VwKHNjb3BlLCAnVnBjJywgeyB2cGNJZDogc2NvcGUubm9kZS50cnlHZXRDb250ZXh0KCd1c2VfdnBjX2lkJykgfSkgOlxuICAgICAgbmV3IGVjMi5WcGMoc2NvcGUsICdWcGMnLCB7IG1heEF6czogMywgbmF0R2F0ZXdheXM6IDEgfSk7XG59XG5cbmZ1bmN0aW9uIHByaW50T3V0cHV0KHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIGtleTogc3RyaW5nIHwgbnVtYmVyKSB7XG4gIG5ldyBjZGsuQ2ZuT3V0cHV0KHNjb3BlLCBpZCwgeyB2YWx1ZTogU3RyaW5nKGtleSkgfSk7XG59XG4iXX0=