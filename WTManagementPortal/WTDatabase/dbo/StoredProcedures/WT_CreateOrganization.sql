CREATE PROCEDURE [dbo].[WT_CreateOrganization]
	@Id UNIQUEIDENTIFIER,
	@InverCloudId UNIQUEIDENTIFIER,
	@Name NVARCHAR(max)
AS

	BEGIN TRY
	
		INSERT INTO Organizations(Id,InverCloud_Id,Name)
		VALUES(@Id,@InverCloudId,@Name)
	
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