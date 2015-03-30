CREATE PROCEDURE [dbo].[WT_DeleteOrganization]
	@Id UNIQUEIDENTIFIER
	
AS

	BEGIN TRY
		
		DELETE
		FROM Users
		WHERE Organization_Id = @Id

		DELETE
		FROM Organizations
		WHERE Id = @Id
	
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