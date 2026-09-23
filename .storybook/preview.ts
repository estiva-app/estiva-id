import type { Preview } from '@storybook/react-vite'

/**
 * Every story file gets its docs page, as it did in Peek's Storybook. Each
 * story file brings its own stylesheet, API answers and location through the
 * harness (`web/src/stories/harness.tsx`), so nothing else is set here.
 */
const preview: Preview = {
  tags: ['autodocs'],
}

export default preview
