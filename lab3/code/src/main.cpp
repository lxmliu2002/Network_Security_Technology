#include "MD5.hpp"

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 4)
    {
        cout << "Parameter Error !" << endl;
        return -1;
    }
    else if ((argc == 2) && (strcmp(argv[1], "-h") == 0))
    {
        cout << "MD5 usage:\t[-h]\t--help information\n";
        cout << "\t\t[-t]\t--test MD5 application\n";
        cout << "\t\t[-c]\t[file path of the file computed]\n";
        cout << "\t\t\t--compute MD5 of the given file\n";
        cout << "\t\t[-v]\t[file path of the file validated]\n";
        cout << "\t\t\t--validate the integrality of a given file by manual input MD5 value\n";
        cout << "\t\t[-f]\t[file path of the file validated]  [file path of the .md5 file]\n";
        cout << "\t\t\t--validate the integrality of a given file by read MD5 value from .md5 file\n";
    }
    else if ((argc == 2) && (strcmp(argv[1], "-t") == 0))
    {
        string strlist[] = {"",
                            "a",
                            "abc",
                            "message digest",
                            "abcdefghijklmnopqrstuvwxyz",
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};
        for (int i = 0; i < 7; i++)
        {
            cout << "MD5(\"" << strlist[i] << "\") = " << MD5(strlist[i]).Tostring() << endl;
        }
    }
    else if ((argc == 3) && (strcmp(argv[1], "-c") == 0))
    {
        if (argv[2] == NULL)
        {
            cout << "Error arameter!" << endl;
            return -1;
        }
        string pFilePath = argv[2];
        ifstream File_1(pFilePath);
        cout << "The MD5 value of file(\"" << pFilePath << "\") is " << MD5(File_1).Tostring() << endl;
    }
    else if ((argc == 3) && (strcmp(argv[1], "-v") == 0))
    {
        if (argv[2] == NULL)
        {
            cout << "Error arameter!" << endl;
            return -1;
        }
        cout << "Please input the MD5 value of file(\"" << argv[2] << "\")..." << endl;
        char InputMD5[33];
        cin >> InputMD5;
        InputMD5[32] = '\0';
        string pFilePath = argv[2];
        ifstream File_2(pFilePath);
        string str = MD5(File_2).Tostring();
        cout << "The MD5 of the file(\"" << argv[2] << "\") is " << str << endl;
        const char *pResult = str.c_str();
        if (strcmp(InputMD5, pResult) != 0)
        {
            cout << "The file is incomplete!" << endl;
            return 0;
        }
        else
        {
            cout << "The file is complete!" << endl;
            return 0;
        }
    }
    else if ((argc == 4) && (strcmp(argv[1], "-f") == 0))
    {
        if (argv[2] == NULL || argv[3] == NULL)
        {
            cout << "Error arameter!" << endl;
            return -1;
        }
        string pFilePath = argv[3];
        ifstream File_3(pFilePath);
        char Record[50];
        File_3.getline(Record, 50);
        char *pMD5 = strtok(Record, "");
        char *pFileName = strtok(NULL, "");
        pFilePath = argv[2];
        ifstream File_4(pFilePath);
        string str = MD5(File_4).Tostring();
        cout << "The MD5 of the file(\"" << argv[2] << "\") is " << str << endl;
        const char *pResult = str.c_str();
        if (strcmp(pMD5, pResult) != 0)
        {
            cout << "The file is incomplete!" << endl;
            return 0;
        }
        else
        {
            cout << "The file is complete!" << endl;
            return 0;
        }
    }
    else
    {
        cout << "Parameter Error !" << endl;
        return -1;
    }
}
