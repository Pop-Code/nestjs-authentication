import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { WsException } from '@nestjs/websockets';

import { forbidden, unauthorized } from '../src';

const http = (response: any) =>
    ({ switchToHttp: () => ({ getResponse: () => response }) }) as unknown as ExecutionContext;

describe('exception factories', () => {
    test('unauthorized() throws a 401 and sets WWW-Authenticate on http (express and fastify)', () => {
        const express = { setHeader: jest.fn() };
        const error = unauthorized({ challenge: 'Bearer' })(http(express), 'http');
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(express.setHeader).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer');

        const fastify = { header: jest.fn() };
        unauthorized({ challenge: 'Bearer realm="api"' })(http(fastify), 'http');
        expect(fastify.header).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer realm="api"');

        expect(unauthorized()(http(express), 'graphql')).toBeInstanceOf(UnauthorizedException);
        expect(unauthorized({ message: 'Login first' })(http({}), 'http').message).toBe('Login first');
    });

    test('unauthorized() converts to WsException and RpcException', () => {
        const ws = unauthorized()(http({}), 'ws');
        expect(ws).toBeInstanceOf(WsException);
        expect((ws as WsException).getError()).toEqual({ status: 401, message: 'Unauthorized' });
        const rpc = unauthorized()(http({}), 'rpc');
        expect(rpc).toBeInstanceOf(RpcException);
        expect((rpc as RpcException).getError()).toEqual({ status: 401, message: 'Unauthorized' });
    });

    test('forbidden() throws a 403 converted to the transport', () => {
        expect(forbidden(http({}), 'http')).toBeInstanceOf(ForbiddenException);
        expect(forbidden(http({}), 'ws')).toBeInstanceOf(WsException);
        expect(forbidden(http({}), 'rpc')).toBeInstanceOf(RpcException);
    });
});
