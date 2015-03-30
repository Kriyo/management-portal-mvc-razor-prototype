CREATE TABLE [dbo].[Organizations]
(
	[Id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
	[InverCloud_Id] UNIQUEIDENTIFIER NOT NULL unique,
	[Name] nvarchar(100) NOT NULL ,

)
