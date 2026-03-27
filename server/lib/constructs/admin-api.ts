import * as cdk from 'aws-cdk-lib';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { FunctionUrl, FunctionUrlAuthType, Runtime, Tracing, Architecture } from 'aws-cdk-lib/aws-lambda';
import { TableV2 } from 'aws-cdk-lib/aws-dynamodb';
import { PolicyStatement, Effect } from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import * as path from 'path';

export interface AdminApiProps {
  readonly environment: string;
  readonly table: TableV2;
  readonly allowedOrigins: string[];
  readonly reservedConcurrency?: number;
}

export class AdminApi extends Construct {
  public readonly handler: NodejsFunction;
  public readonly functionUrl: FunctionUrl;

  constructor(scope: Construct, id: string, props: AdminApiProps) {
    super(scope, id);

    this.handler = new NodejsFunction(this, 'Handler', {
      runtime: Runtime.NODEJS_20_X,
      architecture: Architecture.ARM_64,
      entry: path.join(__dirname, '../admin-handler/index.ts'),
      handler: 'handler',
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      reservedConcurrentExecutions: props.reservedConcurrency ?? 5,
      tracing: Tracing.ACTIVE,
      environment: {
        TABLE_NAME: props.table.tableName,
        ENVIRONMENT: props.environment,
        ALLOWED_ORIGINS: props.allowedOrigins.join(','),
      },
      bundling: {
        minify: true,
        sourceMap: true,
        target: 'node20',
        format: undefined, // default cjs for Lambda
      },
    });

    this.functionUrl = this.handler.addFunctionUrl({
      authType: FunctionUrlAuthType.NONE,
    });

    // DynamoDB read-only access
    this.handler.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:Scan', 'dynamodb:Query', 'dynamodb:GetItem'],
        resources: [props.table.tableArn],
      }),
    );

    // CloudWatch read access
    this.handler.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['cloudwatch:DescribeAlarms', 'cloudwatch:GetMetricData'],
        resources: ['*'],
      }),
    );

    // Cost Explorer read access
    this.handler.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['ce:GetCostAndUsage', 'ce:GetCostForecast'],
        resources: ['*'],
      }),
    );
  }
}
