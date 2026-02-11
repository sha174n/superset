/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import '@testing-library/jest-dom';
import Icicle from '../src/Partition';

jest.mock('@superset-ui/core', () => ({
  ...jest.requireActual('@superset-ui/core'),
  CategoricalColorNamespace: {
    getScale: () => () => '#ffffff',
  },
  getNumberFormatter: () => (x: any) => '' + x,
  getTimeFormatter: () => (x: any) => '' + x,
}));

describe('Partition chart XSS', () => {
  it('should escape XSS payload in tooltip', () => {
    const div = document.createElement('div');
    document.body.appendChild(div);

    const props = {
      data: [{
        name: '<img src=x onerror=alert(1)>',
        val: 10,
        children: []
      }],
      width: 100,
      height: 100,
      colorScheme: 'bnbColors',
      dateTimeFormat: '%Y-%m-%d',
      equalDateSize: false,
      levels: ['a', 'b'],
      metrics: ['sum__num'],
      numberFormat: '.3s',
      partitionLimit: 10,
      partitionThreshold: 0.05,
      timeSeriesOption: 'not_time',
      useLogScale: false,
      useRichTooltip: true,
      sliceId: 1,
    };

    // @ts-ignore
    Icicle(div, props);

    const gs = div.querySelectorAll('g');
    expect(gs.length).toBeGreaterThan(0);

    const g = gs[0];

    const event = new MouseEvent('mouseover', {
      bubbles: true,
      cancelable: true,
      view: window
    });
    g.dispatchEvent(event);

    const tooltip = document.querySelector('.partition-tooltip');
    expect(tooltip).not.toBeNull();
    // Expect the XSS payload to be escaped
    expect(tooltip?.innerHTML).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(tooltip?.innerHTML).not.toContain('<img');
  });
});
