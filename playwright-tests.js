const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false }); // Set headless: true for CI
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Navigate to the login page
    await page.goto('http://localhost:3000');

    // Test: Register a new user
    console.log('Testing registration...');
    await page.fill('form[action="/register"] input[name="username"]', 'testuser');
    await page.fill('form[action="/register"] input[name="password"]', 'password123');
    await page.click('form[action="/register"] button[type="submit"]');
    await page.waitForTimeout(1000); // Wait for the registration to complete

    // Test: Log in with the new user
    console.log('Testing login...');
    await page.fill('form[action="/login"] input[name="username"]', 'testuser');
    await page.fill('form[action="/login"] input[name="password"]', 'password123');
    await page.click('form[action="/login"] button[type="submit"]');
    await page.waitForTimeout(1000); // Wait for the login to complete

    // Verify redirection to the afterlogin page
    if (page.url() !== 'http://localhost:3000/afterlogin') {
      throw new Error('Login failed or redirection did not occur.');
    }

    // Test: Post a new comment
    console.log('Testing posting a comment...');
    await page.fill('form#commentForm input[name="comment"]', 'This is a test comment.');
    await page.click('form#commentForm button[type="submit"]');
    await page.waitForTimeout(1000); // Wait for the comment to be posted

    // Verify the comment appears in the comment list
    const commentText = await page.textContent('#commentList li:last-child span');
    if (commentText !== 'This is a test comment.') {
      throw new Error('Comment was not posted successfully.');
    }

    console.log('All tests passed successfully!');
  } catch (error) {
    console.error('Test failed:', error.message);
  } finally {
    await browser.close();
  }
})();