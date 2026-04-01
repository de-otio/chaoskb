import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockSend } = vi.hoisted(() => ({ mockSend: vi.fn() }));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  QueryCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  UpdateCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

import {
  createNotification,
  handleGetNotifications,
  handleDismissNotification,
  resolveIpLocation,
} from '../../lib/handler/routes/notifications.js';

const TABLE_NAME = 'chaoskb-test';
const TENANT_ID = 'test-tenant';
const ddb = { send: mockSend } as any;

describe('Notification system', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createNotification', () => {
    it('should create a notification record', async () => {
      mockSend.mockResolvedValueOnce({});

      await createNotification(TENANT_ID, 'device_linked', {
        hostname: 'macbook-pro',
        platform: 'darwin',
        location: 'Berlin, Germany',
      }, ddb, TABLE_NAME);

      expect(mockSend).toHaveBeenCalledTimes(1);
    });
  });

  describe('GET /v1/notifications', () => {
    it('should return unacknowledged notifications', async () => {
      mockSend.mockResolvedValueOnce({
        Items: [
          {
            PK: `TENANT#${TENANT_ID}`,
            SK: 'NOTIFICATION#2026-03-30T10:00:00Z#abc123',
            type: 'device_linked',
            deviceInfo: { hostname: 'new-laptop', platform: 'linux' },
            acknowledged: false,
            timestamp: '2026-03-30T10:00:00Z',
          },
        ],
      });

      const result = await handleGetNotifications(TENANT_ID, ddb, TABLE_NAME);

      expect(result.statusCode).toBe(200);
      const parsed = JSON.parse(result.body);
      expect(parsed.notifications).toHaveLength(1);
      expect(parsed.notifications[0].type).toBe('device_linked');
      expect(parsed.notifications[0].deviceInfo.hostname).toBe('new-laptop');
    });

    it('should return empty list when no notifications', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const result = await handleGetNotifications(TENANT_ID, ddb, TABLE_NAME);

      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body).notifications).toHaveLength(0);
    });
  });

  describe('POST /v1/notifications/{id}/dismiss', () => {
    it('should dismiss a notification', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await handleDismissNotification(
        TENANT_ID,
        'NOTIFICATION#2026-03-30T10:00:00Z#abc123',
        ddb,
        TABLE_NAME,
      );

      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body).status).toBe('dismissed');
    });

    it('should return 404 for non-existent notification', async () => {
      const condError = new Error('Condition not met');
      condError.name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(condError);

      const result = await handleDismissNotification(TENANT_ID, 'NOTIFICATION#bad', ddb, TABLE_NAME);

      expect(result.statusCode).toBe(404);
    });
  });

  describe('resolveIpLocation', () => {
    it('should extract city + country from CloudFront headers', () => {
      const headers = {
        'cloudfront-viewer-country': 'DE',
        'cloudfront-viewer-city': 'Berlin',
        'cloudfront-viewer-country-region-name': 'Berlin',
      };

      expect(resolveIpLocation(headers)).toBe('Berlin, Berlin, DE');
    });

    it('should return country only if no city', () => {
      const headers = { 'cloudfront-viewer-country': 'US' };
      expect(resolveIpLocation(headers)).toBe('US');
    });

    it('should return null if no headers', () => {
      expect(resolveIpLocation({})).toBeNull();
    });
  });
});
