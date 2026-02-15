import {
  saveUserCounter,
  getUserCounter,
  updateUserCounter,
  setUserCounter,
} from "./dynamoDbMethods.mjs";

/**
 * Main program to demonstrate saving and managing userId and counter in DynamoDB
 */
async function main() {
  try {
    const userId = "user123";
    const initialCounter = 0;

    console.log("=== DynamoDB User Counter Program ===\n");

    // Example 1: Save a new userId with counter
    console.log("1. Saving new userId with counter...");
    await saveUserCounter(userId, initialCounter);
    console.log("✓ Saved successfully\n");

    // Example 2: Get the userId and counter
    console.log("2. Retrieving userId and counter...");
    const userData = await getUserCounter(userId);
    if (userData) {
      console.log(
        `✓ Retrieved - userId: ${userData.userId}, counter: ${userData.counter}\n`
      );
    }

    // Example 3: Update counter (increment by 1)
    console.log("3. Incrementing counter...");
    const updatedData = await updateUserCounter(userId, 1);
    console.log(`✓ Counter updated to: ${updatedData.counter}\n`);

    // Example 4: Increment counter by a specific amount
    console.log("4. Incrementing counter by 5...");
    const incrementedData = await updateUserCounter(userId, 5);
    console.log(`✓ Counter updated to: ${incrementedData.counter}\n`);

    // Example 5: Set counter to a specific value
    console.log("5. Setting counter to 100...");
    const setData = await setUserCounter(userId, 100);
    console.log(`✓ Counter set to: ${setData.counter}\n`);

    // Example 6: Get final counter value
    console.log("6. Getting final counter value...");
    const finalData = await getUserCounter(userId);
    if (finalData) {
      console.log(
        `✓ Final - userId: ${finalData.userId}, counter: ${finalData.counter}\n`
      );
    }

    console.log("=== Program completed successfully ===");
  } catch (error) {
    console.error("Error in main program:", error);
    process.exit(1);
  }
}

// Run the program
main();
