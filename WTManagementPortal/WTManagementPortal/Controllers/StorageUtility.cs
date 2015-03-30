using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.IO;
using System.Configuration;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;

namespace WTManagementPortal.Controllers
{
    public class StorageUtility
    {
        public void setupStorageAccount() {

            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(
                                ConfigurationManager.ConnectionStrings["StorageConnectionString"].ConnectionString);



            return;

        }

        private bool PutFileToAzure(string FilePath, Guid SnapshotID)
        {

            bool result = false;

            const string account = "wtXXXXt";

            const string key = "7WYsZ6FZVOa0QoAi8wC+2xJLKGsUHImGF2Mp/sSAMArgNCbuEjbXXX8T3AbTeKIq4B+8M3aM1LkNyPDCDFQ==";

            const string url = "http:// wtXXXXt.blob.core.windows.net/test";



            if (File.Exists(FilePath))
            {



   //             AzureBlob AZWriter = new AzureBlob(account, key);

                FileInfo fi = new FileInfo(FilePath);



                int chunksize = 1024 * 1024;

  //              Uri furi = AZWriter.UploadBlob(FilePath, SnapshotID.ToString(), chunksize);





                File.Delete(FilePath);

                result = true;



            }

            else
            {

                throw new Exception(string.Format("Error could not transfer file to azure as the local file doesn't exist: {0}", FilePath));

            }

            return result;

        }
    }
}