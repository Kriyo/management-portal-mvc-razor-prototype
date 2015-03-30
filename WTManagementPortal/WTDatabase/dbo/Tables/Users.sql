CREATE TABLE [dbo].[Users]
(
	[Organization_Id] UNIQUEIDENTIFIER NOT NULL ,
	[Id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
	[InverCloud_Id] bigint NOT NULL UNIQUE,
	[Email] nvarchar(max) NOT NULL,
	[FName] nvarchar(max),
	[LName] nvarchar(max)
	CONSTRAINT fk_UserOrganizations FOREIGN KEY (Organization_Id)
	REFERENCES Organizations(Id)
	
)
