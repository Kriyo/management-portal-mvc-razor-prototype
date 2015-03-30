CREATE PROCEDURE [dbo].[WT_CreateUser]
	@UserId UNIQUEIDENTIFIER,
	@InverCloudOrgId UNIQUEIDENTIFIER,
	@InverCloudUserId bigint,
	@Email NVARCHAR(max),
	@LName nvarchar(max),
	@FName NVARCHAR(max)
AS

	BEGIN TRY
	
		DECLARE @OrgId UNIQUEIDENTIFIER
		SET @OrgId = ( SELECT Id
						FROM Organizations
						WHERE Id = @InverCloudOrgId)

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