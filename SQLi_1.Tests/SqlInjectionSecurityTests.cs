using System;
using System.Data.SqlClient;
using NUnit.Framework;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Comprehensive security tests for SQL injection vulnerability remediation in Program_2.cs
    /// These tests validate that the parameterized query implementation prevents SQL injection attacks
    /// </summary>
    [TestFixture]
    public class SqlInjectionSecurityTests
    {
        private SqlConnection _testConnection;

        [SetUp]
        public void SetUp()
        {
            // Create a test connection (will not be opened, just used to create commands)
            _testConnection = new SqlConnection("Server=testserver;Database=testdb;");
        }

        [TearDown]
        public void TearDown()
        {
            _testConnection?.Dispose();
        }

        #region Parameterized Query Validation Tests

        [Test]
        [Description("Validates that the SQL command uses parameterized query with @username placeholder")]
        public void CreateLoginCommand_UsesParameterizedQuery_ContainsUsernameParameter()
        {
            // Arrange
            string testUsername = "testuser";
            string testPassword = "testpass";

            // Act
            var cmd = Program.CreateLoginCommand(testUsername, testPassword, _testConnection);

            // Assert
            Assert.IsNotNull(cmd, "Command should not be null");
            Assert.IsTrue(cmd.CommandText.Contains("@username"),
                "SQL command should use @username parameter placeholder");
            Assert.IsFalse(cmd.CommandText.Contains(testUsername),
                "SQL command should NOT contain the actual username value - should use parameters instead");
        }

        [Test]
        [Description("Validates that the SQL command uses parameterized query with @password placeholder")]
        public void CreateLoginCommand_UsesParameterizedQuery_ContainsPasswordParameter()
        {
            // Arrange
            string testUsername = "testuser";
            string testPassword = "testpass";

            // Act
            var cmd = Program.CreateLoginCommand(testUsername, testPassword, _testConnection);

            // Assert
            Assert.IsTrue(cmd.CommandText.Contains("@password"),
                "SQL command should use @password parameter placeholder");
            Assert.IsFalse(cmd.CommandText.Contains(testPassword),
                "SQL command should NOT contain the actual password value - should use parameters instead");
        }

        [Test]
        [Description("Validates that SQL parameters are properly added to the command")]
        public void CreateLoginCommand_AddsParametersToCommand_HasExpectedParameterCount()
        {
            // Arrange
            string testUsername = "testuser";
            string testPassword = "testpass";

            // Act
            var cmd = Program.CreateLoginCommand(testUsername, testPassword, _testConnection);

            // Assert
            Assert.AreEqual(2, cmd.Parameters.Count,
                "Command should have exactly 2 parameters (username and password)");
        }

        [Test]
        [Description("Validates that the username parameter is correctly set")]
        public void CreateLoginCommand_UsernameParameter_HasCorrectValue()
        {
            // Arrange
            string testUsername = "testuser";
            string testPassword = "testpass";

            // Act
            var cmd = Program.CreateLoginCommand(testUsername, testPassword, _testConnection);

            // Assert
            Assert.IsTrue(cmd.Parameters.Contains("@username"),
                "Command should contain @username parameter");
            Assert.AreEqual(testUsername, cmd.Parameters["@username"].Value,
                "Username parameter should have the correct value");
        }

        [Test]
        [Description("Validates that the password parameter is correctly set")]
        public void CreateLoginCommand_PasswordParameter_HasCorrectValue()
        {
            // Arrange
            string testUsername = "testuser";
            string testPassword = "testpass";

            // Act
            var cmd = Program.CreateLoginCommand(testUsername, testPassword, _testConnection);

            // Assert
            Assert.IsTrue(cmd.Parameters.Contains("@password"),
                "Command should contain @password parameter");
            Assert.AreEqual(testPassword, cmd.Parameters["@password"].Value,
                "Password parameter should have the correct value");
        }

        #endregion

        #region SQL Injection Attack Prevention Tests

        [Test]
        [Description("Tests that SQL injection using OR 1=1 attack is neutralized by parameterization")]
        public void CreateLoginCommand_WithSqlInjectionAttempt_Or1Equals1_IsSafelyParameterized()
        {
            // Arrange - Classic SQL injection payload
            string maliciousUsername = "admin' OR '1'='1";
            string password = "anything";

            // Act
            var cmd = Program.CreateLoginCommand(maliciousUsername, password, _testConnection);

            // Assert
            // The malicious input should be treated as a literal string value, not as SQL code
            Assert.AreEqual(maliciousUsername, cmd.Parameters["@username"].Value,
                "Malicious username should be safely stored as parameter value");
            Assert.IsFalse(cmd.CommandText.Contains("OR '1'='1'"),
                "SQL injection payload should NOT appear in the command text");

            // Verify the command structure remains safe
            Assert.IsTrue(cmd.CommandText.Contains("@username"),
                "Command should still use parameter placeholder");
        }

        [Test]
        [Description("Tests that SQL injection using UNION SELECT attack is neutralized")]
        public void CreateLoginCommand_WithSqlInjectionAttempt_UnionSelect_IsSafelyParameterized()
        {
            // Arrange - UNION-based SQL injection payload
            string maliciousUsername = "admin' UNION SELECT * FROM Users--";
            string password = "password";

            // Act
            var cmd = Program.CreateLoginCommand(maliciousUsername, password, _testConnection);

            // Assert
            Assert.AreEqual(maliciousUsername, cmd.Parameters["@username"].Value,
                "Malicious UNION payload should be safely stored as parameter value");
            Assert.IsFalse(cmd.CommandText.Contains("UNION SELECT"),
                "UNION SELECT attack should NOT appear in the command text");

            // Verify parameterization is maintained
            Assert.AreEqual(2, cmd.Parameters.Count,
                "Parameter count should remain exactly 2");
        }

        [Test]
        [Description("Tests that SQL injection using comment attack is neutralized")]
        public void CreateLoginCommand_WithSqlInjectionAttempt_CommentAttack_IsSafelyParameterized()
        {
            // Arrange - Comment-based SQL injection to bypass password check
            string maliciousUsername = "admin'--";
            string password = "ignored";

            // Act
            var cmd = Program.CreateLoginCommand(maliciousUsername, password, _testConnection);

            // Assert
            Assert.AreEqual(maliciousUsername, cmd.Parameters["@username"].Value,
                "Username with comment should be safely stored as parameter value");

            // The password parameter should still be present (not commented out in SQL)
            Assert.IsTrue(cmd.Parameters.Contains("@password"),
                "Password parameter should still be present - comment attack should be neutralized");
            Assert.AreEqual(2, cmd.Parameters.Count,
                "Both parameters should be present despite comment in username");
        }

        [Test]
        [Description("Tests that SQL injection using DROP TABLE attack is neutralized")]
        public void CreateLoginCommand_WithSqlInjectionAttempt_DropTable_IsSafelyParameterized()
        {
            // Arrange - Destructive SQL injection payload
            string maliciousUsername = "admin'; DROP TABLE Users; --";
            string password = "password";

            // Act
            var cmd = Program.CreateLoginCommand(maliciousUsername, password, _testConnection);

            // Assert
            Assert.AreEqual(maliciousUsername, cmd.Parameters["@username"].Value,
                "DROP TABLE payload should be safely stored as parameter value");
            Assert.IsFalse(cmd.CommandText.Contains("DROP TABLE"),
                "Destructive DROP TABLE command should NOT appear in command text");
        }

        [Test]
        [Description("Tests that SQL injection in password field is also neutralized")]
        public void CreateLoginCommand_WithSqlInjectionInPassword_IsSafelyParameterized()
        {
            // Arrange - SQL injection via password field
            string username = "normaluser";
            string maliciousPassword = "' OR '1'='1";

            // Act
            var cmd = Program.CreateLoginCommand(username, maliciousPassword, _testConnection);

            // Assert
            Assert.AreEqual(maliciousPassword, cmd.Parameters["@password"].Value,
                "Malicious password should be safely stored as parameter value");
            Assert.IsFalse(cmd.CommandText.Contains("OR '1'='1'"),
                "SQL injection payload should NOT appear in the command text");
        }

        [Test]
        [Description("Tests that stacked queries attack is neutralized")]
        public void CreateLoginCommand_WithStackedQueriesAttack_IsSafelyParameterized()
        {
            // Arrange - Stacked queries SQL injection
            string maliciousUsername = "admin'; INSERT INTO Users VALUES ('hacker', 'pass'); --";
            string password = "password";

            // Act
            var cmd = Program.CreateLoginCommand(maliciousUsername, password, _testConnection);

            // Assert
            Assert.AreEqual(maliciousUsername, cmd.Parameters["@username"].Value,
                "Stacked query payload should be safely stored as parameter value");
            Assert.IsFalse(cmd.CommandText.Contains("INSERT INTO"),
                "Stacked INSERT query should NOT appear in command text");
        }

        #endregion

        #region Edge Cases and Special Characters Tests

        [Test]
        [Description("Tests that legitimate special characters in usernames are handled correctly")]
        public void CreateLoginCommand_WithLegitimateSpecialCharacters_HandlesCorrectly()
        {
            // Arrange - Legitimate usernames with special chars that might look suspicious
            string username = "user@email.com";
            string password = "P@ssw0rd!";

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                "Legitimate special characters should be preserved");
            Assert.AreEqual(password, cmd.Parameters["@password"].Value,
                "Password with special characters should be preserved");
            Assert.AreEqual(2, cmd.Parameters.Count,
                "Parameter count should remain 2");
        }

        [Test]
        [Description("Tests that empty string inputs are handled safely")]
        public void CreateLoginCommand_WithEmptyStrings_HandlesCorrectly()
        {
            // Arrange
            string username = "";
            string password = "";

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                "Empty username should be handled");
            Assert.AreEqual(password, cmd.Parameters["@password"].Value,
                "Empty password should be handled");
        }

        [Test]
        [Description("Tests that very long input strings are handled safely")]
        public void CreateLoginCommand_WithVeryLongStrings_HandlesCorrectly()
        {
            // Arrange - Very long strings that might cause buffer issues
            string username = new string('a', 1000) + "' OR '1'='1";
            string password = new string('b', 1000);

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                "Long username with injection attempt should be safely parameterized");
            Assert.AreEqual(password, cmd.Parameters["@password"].Value,
                "Long password should be safely parameterized");
        }

        [Test]
        [Description("Tests that unicode characters are handled safely")]
        public void CreateLoginCommand_WithUnicodeCharacters_HandlesCorrectly()
        {
            // Arrange - Unicode characters that might cause encoding issues
            string username = "用户名' OR '1'='1";
            string password = "пароль";

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                "Unicode username with injection attempt should be safely parameterized");
            Assert.AreEqual(password, cmd.Parameters["@password"].Value,
                "Unicode password should be safely parameterized");
        }

        [Test]
        [Description("Tests that null values are handled appropriately")]
        public void CreateLoginCommand_WithNullValues_HandlesCorrectly()
        {
            // Arrange
            string username = null;
            string password = null;

            // Act & Assert
            // The method should handle nulls gracefully (either through parameters or validation)
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            Assert.IsNotNull(cmd, "Command should be created even with null inputs");
            Assert.AreEqual(2, cmd.Parameters.Count,
                "Parameters should still be added even if null");
        }

        #endregion

        #region Command Structure Validation Tests

        [Test]
        [Description("Validates that the SQL command structure is correct")]
        public void CreateLoginCommand_CommandStructure_IsCorrectlyFormed()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            Assert.IsNotNull(cmd.CommandText, "Command text should not be null");
            Assert.IsTrue(cmd.CommandText.Contains("SELECT"),
                "Command should be a SELECT statement");
            Assert.IsTrue(cmd.CommandText.Contains("FROM Users"),
                "Command should query the Users table");
            Assert.IsTrue(cmd.CommandText.Contains("WHERE"),
                "Command should have a WHERE clause");
        }

        [Test]
        [Description("Validates that the command uses AND operator correctly")]
        public void CreateLoginCommand_UsesAndOperator_BetweenUsernameAndPassword()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            Assert.IsTrue(cmd.CommandText.Contains("AND"),
                "Command should use AND operator between username and password conditions");

            // Verify that the parameters are in the correct order in the query
            int usernamePos = cmd.CommandText.IndexOf("@username");
            int passwordPos = cmd.CommandText.IndexOf("@password");
            Assert.IsTrue(usernamePos < passwordPos,
                "Username parameter should appear before password parameter in query");
        }

        [Test]
        [Description("Validates that the command connection is set correctly")]
        public void CreateLoginCommand_ConnectionProperty_IsSetCorrectly()
        {
            // Arrange
            string username = "testuser";
            string password = "testpass";

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            Assert.AreSame(_testConnection, cmd.Connection,
                "Command connection should be set to the provided connection");
        }

        #endregion

        #region Regression Prevention Tests

        [Test]
        [Description("Regression test: Ensures no string concatenation is used in SQL query construction")]
        public void CreateLoginCommand_DoesNotUseConcatenation_ForSqlConstruction()
        {
            // Arrange
            string username = "test' + 'user";
            string password = "test' + 'pass";

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            // If concatenation was used, the + symbols might affect the query structure
            Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                "Username with + symbols should be treated as literal value");
            Assert.AreEqual(password, cmd.Parameters["@password"].Value,
                "Password with + symbols should be treated as literal value");

            // The command text should not contain the actual input values
            Assert.IsFalse(cmd.CommandText.Contains("test' + 'user"),
                "Command text should not contain concatenated username value");
        }

        [Test]
        [Description("Regression test: Ensures quote escaping is not attempted (parameters handle it)")]
        public void CreateLoginCommand_DoesNotEscapeQuotes_ParametersHandleIt()
        {
            // Arrange
            string username = "user''name";  // Double quote might indicate manual escaping
            string password = "pass''word";

            // Act
            var cmd = Program.CreateLoginCommand(username, password, _testConnection);

            // Assert
            // Parameters should handle the quotes correctly without manual escaping
            Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                "Quotes in username should be preserved as-is by parameters");
            Assert.AreEqual(password, cmd.Parameters["@password"].Value,
                "Quotes in password should be preserved as-is by parameters");
        }

        #endregion
    }
}
