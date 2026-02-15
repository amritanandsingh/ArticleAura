import "dotenv/config";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({
  region: process.env.AWS_REGION || "ap-south-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    // sessionToken: process.env.AWS_SESSION_TOKEN, // if using temp creds
  },
});

const ddb = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.APP_TABLE_NAME || "ArticleAuraTable";

/**
 * Save or update userId and counter in DynamoDB
 * @param {string} userId - The user ID
 * @param {number} counter - The counter value
 * @returns {Promise<Object>} The saved item
 */
export async function saveUserCounter(userId, counter) {
  try {
    const params = {
      TableName: TABLE_NAME,
      Item: {
        userId: userId,
        counter: counter,
        updatedAt: new Date().toISOString(),
      },
    };

    const result = await ddb.send(new PutCommand(params));
    console.log(
      `Successfully saved userId: ${userId} with counter: ${counter}`
    );
    return params.Item;
  } catch (error) {
    console.error("Error saving user counter:", error);
    throw error;
  }
}

/**
 * Get userId and counter from DynamoDB
 * @param {string} userId - The user ID to retrieve
 * @returns {Promise<Object|null>} The user counter data or null if not found
 */
export async function getUserCounter(userId) {
  try {
    const params = {
      TableName: TABLE_NAME,
      Key: {
        userId: userId,
      },
    };

    const result = await ddb.send(new GetCommand(params));

    if (result.Item) {
      console.log(
        `Retrieved userId: ${userId}, counter: ${result.Item.counter}`
      );
      return result.Item;
    } else {
      console.log(`No record found for userId: ${userId}`);
      return null;
    }
  } catch (error) {
    console.error("Error getting user counter:", error);
    throw error;
  }
}

/**
 * Update counter for an existing userId (increments by default)
 * @param {string} userId - The user ID
 * @param {number} incrementBy - Amount to increment counter (default: 1)
 * @returns {Promise<Object>} The updated item
 */
export async function updateUserCounter(userId, incrementBy = 1) {
  try {
    const params = {
      TableName: TABLE_NAME,
      Key: {
        userId: userId,
      },
      UpdateExpression: "SET counter = counter + :inc, updatedAt = :timestamp",
      ExpressionAttributeValues: {
        ":inc": incrementBy,
        ":timestamp": new Date().toISOString(),
      },
      ReturnValues: "ALL_NEW",
    };

    const result = await ddb.send(new UpdateCommand(params));
    console.log(
      `Updated userId: ${userId}, new counter: ${result.Attributes.counter}`
    );
    return result.Attributes;
  } catch (error) {
    // If item doesn't exist, create it with initial counter value
    if (
      error.name === "ValidationException" ||
      error.name === "ResourceNotFoundException"
    ) {
      console.log(
        `User ${userId} not found, creating new record with counter: ${incrementBy}`
      );
      return await saveUserCounter(userId, incrementBy);
    }
    console.error("Error updating user counter:", error);
    throw error;
  }
}

/**
 * Set counter to a specific value for userId
 * @param {string} userId - The user ID
 * @param {number} counter - The counter value to set
 * @returns {Promise<Object>} The updated item
 */
export async function setUserCounter(userId, counter) {
  try {
    const params = {
      TableName: TABLE_NAME,
      Key: {
        userId: userId,
      },
      UpdateExpression: "SET counter = :counter, updatedAt = :timestamp",
      ExpressionAttributeValues: {
        ":counter": counter,
        ":timestamp": new Date().toISOString(),
      },
      ReturnValues: "ALL_NEW",
    };

    const result = await ddb.send(new UpdateCommand(params));
    console.log(`Set userId: ${userId} counter to: ${counter}`);
    return result.Attributes;
  } catch (error) {
    // If item doesn't exist, create it
    if (
      error.name === "ValidationException" ||
      error.name === "ResourceNotFoundException"
    ) {
      console.log(
        `User ${userId} not found, creating new record with counter: ${counter}`
      );
      return await saveUserCounter(userId, counter);
    }
    console.error("Error setting user counter:", error);
    throw error;
  }
}
