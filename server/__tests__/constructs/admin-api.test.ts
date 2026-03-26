import { describe, it } from 'vitest';
import { App, Stack } from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { BlobStore } from '../../lib/constructs/blob-store.js';
import { AdminApi } from '../../lib/constructs/admin-api.js';

describe('AdminApi construct', () => {
  function createTemplate(allowedOrigins: string[] = []): Template {
    const app = new App();
    const stack = new Stack(app, 'TestStack');
    const blobStore = new BlobStore(stack, 'BlobStore', { environment: 'test' });
    new AdminApi(stack, 'AdminApi', {
      table: blobStore.table,
      environment: 'test',
      allowedOrigins,
    });
    return Template.fromStack(stack);
  }

  it('should create a Lambda function with correct runtime, memory, and timeout', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs20.x',
      MemorySize: 256,
      Timeout: 30,
    });
  });

  it('should have ARM64 architecture', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Function', {
      Architectures: ['arm64'],
    });
  });

  it('should have reserved concurrency of 5', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Function', {
      ReservedConcurrentExecutions: 5,
    });
  });

  it('should have X-Ray tracing enabled', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Function', {
      TracingConfig: {
        Mode: 'Active',
      },
    });
  });

  it('should have environment variables set', () => {
    const template = createTemplate(['https://chaoskb.com', 'https://dev.chaoskb.com']);

    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: Match.objectLike({
          ENVIRONMENT: 'test',
          ALLOWED_ORIGINS: 'https://chaoskb.com,https://dev.chaoskb.com',
        }),
      },
    });
  });

  it('should create a Function URL with no auth', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Url', {
      AuthType: 'NONE',
    });
  });

  it('should have DynamoDB read permissions', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Action: ['dynamodb:Scan', 'dynamodb:Query', 'dynamodb:GetItem'],
          }),
        ]),
      },
    });
  });

  it('should have CloudWatch read permissions', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Action: ['cloudwatch:DescribeAlarms', 'cloudwatch:GetMetricData'],
          }),
        ]),
      },
    });
  });

  it('should have Cost Explorer permissions', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Action: ['ce:GetCostAndUsage', 'ce:GetCostForecast'],
          }),
        ]),
      },
    });
  });
});
