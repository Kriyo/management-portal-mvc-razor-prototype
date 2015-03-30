﻿/*
Deployment script for WTManagementPortal

This code was generated by a tool.
Changes to this file may cause incorrect behavior and will be lost if
the code is regenerated.
*/

GO
SET ANSI_NULLS, ANSI_PADDING, ANSI_WARNINGS, ARITHABORT, CONCAT_NULL_YIELDS_NULL, QUOTED_IDENTIFIER ON;

SET NUMERIC_ROUNDABORT OFF;


GO
:setvar DatabaseName "WTManagementPortal"
:setvar DefaultFilePrefix "WTManagementPortal"
:setvar DefaultDataPath "C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\"
:setvar DefaultLogPath "C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\"

GO
:on error exit
GO
/*
Detect SQLCMD mode and disable script execution if SQLCMD mode is not supported.
To re-enable the script after enabling SQLCMD mode, execute the following:
SET NOEXEC OFF; 
*/
:setvar __IsSqlCmdEnabled "True"
GO
IF N'$(__IsSqlCmdEnabled)' NOT LIKE N'True'
    BEGIN
        PRINT N'SQLCMD mode must be enabled to successfully execute this script.';
        SET NOEXEC ON;
    END


GO
USE [$(DatabaseName)];


GO
PRINT N'Creating [dbo].[WT_CreateUser]...';


GO
CREATE PROCEDURE [dbo].[WT_CreateUser]
	@UserId UNIQUEIDENTIFIER,
	@InverCloudOrgId UNIQUEIDENTIFIER,
	@InverCloudUserId UNIQUEIDENTIFIER,
	@Email NVARCHAR(max),
	@LName nvarchar(max),
	@FName NVARCHAR(max)
AS

	BEGIN TRY
	
		DECLARE @OrgId UNIQUEIDENTIFIER
		SET @OrgId = ( SELECT Id
						FROM Organizations
						WHERE InverCloud_Id = @InverCloudOrgId)

		INSERT INTO Users(Organization_Id,Id,InverCloud_Id,Email,FName,LName)
		VALUES(@OrgId,@UserId,@InverCloudUserId,@Email,@FName,@LName)
	
		return 0

	END TRY
	
	BEGIN CATCH
	
		-- Catch details of error
		DECLARE @ErrMsg nvarchar(4000)
		DECLARE @ERrSeverity int
		DECLARE @ErrState int
		
		SELECT 
			@ErrMsg = ERROR_MESSAGE(),
			@ErrSeverity = ERROR_SEVERITY(),
			@ErrState = ERROR_STATE()
		
			
		-- Throw the error
		RAISERROR( @ErrMsg, @ErrSeverity, @ErrState)

		return -1
		
	END CATCH
GO
PRINT N'Update complete.';


GO
