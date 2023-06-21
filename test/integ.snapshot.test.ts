import { assertions } from 'aws-cdk-lib';
import { IntegTesting } from '../src/integ.default';

test.skip('integ snapshot validation', () => {
  const integ = new IntegTesting();
  integ.stack.forEach(stack => {
    const t = assertions.Template.fromStack(stack);
    expect(t).toMatchSnapshot();
  });
});
