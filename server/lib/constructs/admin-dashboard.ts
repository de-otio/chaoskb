import { Duration } from 'aws-cdk-lib';
import {
  Dashboard,
  GraphWidget,
  Metric,
  Alarm,
  ComparisonOperator,
  TreatMissingData,
  MathExpression,
  Unit,
} from 'aws-cdk-lib/aws-cloudwatch';
import { SnsAction } from 'aws-cdk-lib/aws-cloudwatch-actions';
import { Topic } from 'aws-cdk-lib/aws-sns';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { TableV2 } from 'aws-cdk-lib/aws-dynamodb';
import { LogGroup, MetricFilter, FilterPattern } from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export interface AdminDashboardProps {
  readonly environment: string;
  readonly lambdaFunction: NodejsFunction;
  readonly table: TableV2;
  readonly lambdaLogGroup?: LogGroup;
}

export class AdminDashboard extends Construct {
  public readonly alarmTopic: Topic;
  public readonly dashboard: Dashboard;

  constructor(scope: Construct, id: string, props: AdminDashboardProps) {
    super(scope, id);

    this.alarmTopic = new Topic(this, 'AlarmTopic', {
      displayName: `ChaosKB ${props.environment} Alarms`,
    });

    const snsAction = new SnsAction(this.alarmTopic);

    // Lambda metrics
    const invocations = props.lambdaFunction.metricInvocations({ period: Duration.minutes(5) });
    const errors = props.lambdaFunction.metricErrors({ period: Duration.minutes(5) });
    const durationP50 = props.lambdaFunction.metricDuration({ period: Duration.minutes(5), statistic: 'p50' });
    const durationP95 = props.lambdaFunction.metricDuration({ period: Duration.minutes(5), statistic: 'p95' });
    const durationP99 = props.lambdaFunction.metricDuration({ period: Duration.minutes(5), statistic: 'p99' });

    // DynamoDB metrics
    const readCapacity = new Metric({
      namespace: 'AWS/DynamoDB',
      metricName: 'ConsumedReadCapacityUnits',
      dimensionsMap: { TableName: props.table.tableName },
      period: Duration.minutes(5),
      statistic: 'Sum',
    });

    const writeCapacity = new Metric({
      namespace: 'AWS/DynamoDB',
      metricName: 'ConsumedWriteCapacityUnits',
      dimensionsMap: { TableName: props.table.tableName },
      period: Duration.minutes(5),
      statistic: 'Sum',
    });

    const throttledRequests = new Metric({
      namespace: 'AWS/DynamoDB',
      metricName: 'ThrottledRequests',
      dimensionsMap: { TableName: props.table.tableName },
      period: Duration.minutes(1),
      statistic: 'Sum',
    });

    // Dashboard
    this.dashboard = new Dashboard(this, 'Dashboard', {
      // CDK auto-generates the dashboard name
      widgets: [
        [
          new GraphWidget({
            title: 'Lambda Invocations & Errors',
            left: [invocations],
            right: [errors],
            width: 12,
          }),
          new GraphWidget({
            title: 'Lambda Duration (p50/p95/p99)',
            left: [durationP50, durationP95, durationP99],
            width: 12,
          }),
        ],
        [
          new GraphWidget({
            title: 'DynamoDB Read/Write Capacity',
            left: [readCapacity],
            right: [writeCapacity],
            width: 12,
          }),
          new GraphWidget({
            title: 'DynamoDB Throttled Requests',
            left: [throttledRequests],
            width: 12,
          }),
        ],
      ],
    });

    // Alarms

    // Lambda error rate > 1% over 5 min
    const errorRate = new MathExpression({
      expression: 'IF(invocations > 0, 100 * errors / invocations, 0)',
      usingMetrics: {
        errors,
        invocations,
      },
      period: Duration.minutes(5),
    });

    const errorRateAlarm = new Alarm(this, 'LambdaErrorRateAlarm', {
      alarmDescription: 'Lambda error rate exceeds 1%',
      metric: errorRate,
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: TreatMissingData.NOT_BREACHING,
    });
    errorRateAlarm.addAlarmAction(snsAction);

    // DynamoDB throttles > 0 over 1 min
    const throttleAlarm = new Alarm(this, 'DynamoThrottleAlarm', {
      alarmDescription: 'DynamoDB throttled requests detected',
      metric: throttledRequests,
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: TreatMissingData.NOT_BREACHING,
    });
    throttleAlarm.addAlarmAction(snsAction);

    // Lambda duration p99 > 5s
    const durationAlarm = new Alarm(this, 'LambdaDurationAlarm', {
      alarmDescription: 'Lambda p99 duration exceeds 5 seconds',
      metric: props.lambdaFunction.metricDuration({
        period: Duration.minutes(5),
        statistic: 'p99',
        unit: Unit.MILLISECONDS,
      }),
      threshold: 5000,
      evaluationPeriods: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: TreatMissingData.NOT_BREACHING,
    });
    durationAlarm.addAlarmAction(snsAction);

    // Metric filters for sync operations and auth failures (if log group provided)
    if (props.lambdaLogGroup) {
      const _syncOpsFilter = new MetricFilter(this, 'SyncOpsMetricFilter', {
        logGroup: props.lambdaLogGroup,
        filterPattern: FilterPattern.literal('{ $.operation = "sync" }'),
        metricNamespace: 'ChaosKB',
        metricName: 'SyncOperations',
        metricValue: '1',
      });

      const _authFailuresFilter = new MetricFilter(this, 'AuthFailuresMetricFilter', {
        logGroup: props.lambdaLogGroup,
        filterPattern: FilterPattern.literal('{ $.error = "auth_error" }'),
        metricNamespace: 'ChaosKB',
        metricName: 'AuthFailures',
        metricValue: '1',
      });

      const syncOpsMetric = new Metric({
        namespace: 'ChaosKB',
        metricName: 'SyncOperations',
        period: Duration.minutes(5),
        statistic: 'Sum',
      });

      const authFailuresMetric = new Metric({
        namespace: 'ChaosKB',
        metricName: 'AuthFailures',
        period: Duration.minutes(5),
        statistic: 'Sum',
      });

      const authFailuresAlarm = new Alarm(this, 'AuthFailuresAlarm', {
        alarmDescription: 'Auth failures exceed 10 in 5 minutes',
        metric: authFailuresMetric,
        threshold: 10,
        evaluationPeriods: 1,
        comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: TreatMissingData.NOT_BREACHING,
      });
      authFailuresAlarm.addAlarmAction(snsAction);

      this.dashboard.addWidgets(
        new GraphWidget({
          title: 'Sync Operations',
          left: [syncOpsMetric],
          width: 12,
        }),
        new GraphWidget({
          title: 'Auth Failures',
          left: [authFailuresMetric],
          width: 12,
        }),
      );
    }
  }
}
