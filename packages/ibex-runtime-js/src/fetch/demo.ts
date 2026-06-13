/**
 * Demo script to test the fetch implementation.
 *
 * Run with: bun src/runtime/fetch/demo.ts
 */

import {
  fetch,
  setNativeFetchModule,
  Headers,
  Request,
  Response,
  type NativeFetchModule,
  type NativeResponse,
} from './index.js';

// =============================================================================
// Mock Native Module (simulates what Swift/Kotlin would provide)
// =============================================================================

const mockNativeModule: NativeFetchModule = {
  async fetch(url, init, body) {
    console.log(`[Native] ${init.method} ${url}`);
    if (body) {
      console.log(`[Native] Body: ${new TextDecoder().decode(body)}`);
    }

    // Simulate different responses based on URL
    if (url.includes('jsonplaceholder')) {
      // Simulate a real API response
      const mockData = { userId: 1, id: 1, title: 'Test Post', completed: false };
      return {
        status: 200,
        statusText: 'OK',
        headers: [['content-type', 'application/json']],
        url,
        redirected: false,
        body: new TextEncoder().encode(JSON.stringify(mockData)).buffer,
      };
    }

    if (url.includes('/error')) {
      return {
        status: 500,
        statusText: 'Internal Server Error',
        headers: [],
        url,
        redirected: false,
        body: new TextEncoder().encode('Something went wrong').buffer,
      };
    }

    // Default mock response
    return {
      status: 200,
      statusText: 'OK',
      headers: [['content-type', 'text/plain']],
      url,
      redirected: false,
      body: new TextEncoder().encode('Hello from mock!').buffer,
    };
  },
};

// Initialize the native module
setNativeFetchModule(mockNativeModule);

// =============================================================================
// Test Cases
// =============================================================================

async function testHeaders() {
  console.log('\n=== Testing Headers ===');

  const headers = new Headers({
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token123',
  });

  console.log('Content-Type:', headers.get('content-type'));
  console.log('Has Authorization:', headers.has('authorization'));

  headers.append('Accept', 'application/json');
  headers.append('Accept', 'text/plain');
  console.log('Accept (combined):', headers.get('accept'));

  console.log('All headers:');
  for (const [name, value] of headers) {
    console.log(`  ${name}: ${value}`);
  }
}

async function testRequest() {
  console.log('\n=== Testing Request ===');

  const request = new Request('https://api.example.com/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'John Doe' }),
  });

  console.log('Method:', request.method);
  console.log('URL:', request.url);
  console.log('Content-Type:', request.headers.get('content-type'));
  console.log('Body:', await request.text());
}

async function testResponse() {
  console.log('\n=== Testing Response ===');

  // String body
  const textResponse = new Response('Hello, World!');
  console.log('Text response:', await textResponse.text());

  // JSON response
  const jsonResponse = Response.json({ message: 'Success', code: 200 });
  console.log('JSON response:', await jsonResponse.json());

  // Redirect response
  const redirectResponse = Response.redirect('https://example.com/new-location', 302);
  console.log('Redirect status:', redirectResponse.status);
  console.log('Redirect location:', redirectResponse.headers.get('location'));

  // Error response
  const errorResponse = Response.error();
  console.log('Error response type:', errorResponse.type);
}

async function testFetch() {
  console.log('\n=== Testing fetch() ===');

  // Simple GET request
  console.log('\n--- GET Request ---');
  const getResponse = await fetch('https://jsonplaceholder.typicode.com/todos/1');
  console.log('Status:', getResponse.status);
  console.log('OK:', getResponse.ok);
  const getData = await getResponse.json();
  console.log('Data:', getData);

  // POST request with body
  console.log('\n--- POST Request ---');
  const postResponse = await fetch('https://api.example.com/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Jane Doe', email: 'jane@example.com' }),
  });
  console.log('Status:', postResponse.status);

  // Request with custom headers
  console.log('\n--- Request with Headers ---');
  const authResponse = await fetch('https://api.example.com/protected', {
    headers: {
      'Authorization': 'Bearer my-secret-token',
      'X-Custom-Header': 'custom-value',
    },
  });
  console.log('Status:', authResponse.status);
}

async function testAbort() {
  console.log('\n=== Testing AbortController ===');

  const controller = new AbortController();

  // Abort immediately
  controller.abort();

  try {
    await fetch('https://api.example.com/slow', {
      signal: controller.signal,
    });
  } catch (error) {
    console.log('Caught abort error:', (error as Error).message);
  }
}

async function testClone() {
  console.log('\n=== Testing clone() ===');

  const response = await fetch('https://api.example.com/data');
  const clone = response.clone();

  // Both can be read independently
  const text1 = await response.text();
  const text2 = await clone.text();

  console.log('Original:', text1);
  console.log('Clone:', text2);
  console.log('Match:', text1 === text2);
}

// Run all tests
async function main() {
  console.log('Fetch API Implementation Demo');
  console.log('==============================');

  await testHeaders();
  await testRequest();
  await testResponse();
  await testFetch();
  await testAbort();
  await testClone();

  console.log('\n✅ All demos completed!');
}

main().catch(console.error);
