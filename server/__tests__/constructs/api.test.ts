import { describe, it } from 'vitest';
import { App, Stack } from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { BlobStore } from '../../lib/constructs/blob-store.js';
import { Auth } from '../../lib/constructs/auth.js';
import { Api } from '../../lib/constructs/api.js';

describe('Api construct', () => {
  function createTemplate(reservedConcurrency?: number): Template {
    const app = new App();
    const stack = new Stack(app, 'TestStack');
    const blobStore = new BlobStore(stack, 'BlobStore', { environment: 'test' });
    const auth = new Auth(stack, 'Auth', { environment: 'test' });
    new Api(stack, 'Api', {
      table: blobStore.table,
      environment: 'test',
      signupsEnabledParam: auth.signupsEnabledParam,
      reservedConcurrency,
    });
    return Template.fromStack(stack);
  }

  it('should create a Lambda function with Node.js 20 runtime', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs20.x',
      MemorySize: 256,
      Timeout: 30,
    });
  });

  it('should have environment variables set', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: Match.objectLike({
          ENVIRONMENT: 'test',
        }),
      },
    });
  });

  it('should have reserved concurrency (default 10)', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Function', {
      ReservedConcurrentExecutions: 10,
    });
  });

  it('should allow configurable reserved concurrency', () => {
    const template = createTemplate(25);

    template.hasResourceProperties('AWS::Lambda::Function', {
      ReservedConcurrentExecutions: 25,
    });
  });

  it('should create a Function URL', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Url', {
      AuthType: 'NONE',
    });
  });

  it('should create a dead letter queue', () => {
    const template = createTemplate();

    template.hasResource('AWS::SQS::Queue', {});
  });

  it('should have X-Ray tracing enabled', () => {
    const template = createTemplate();

    template.hasResourceProperties('AWS::Lambda::Function', {
      TracingConfig: {
        Mode: 'Active',
      },
    });
  });
});
