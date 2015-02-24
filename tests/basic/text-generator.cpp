#include "text-generator.hpp"

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QTextStream>

#if defined(Q_OS_WIN32)
#	define snprintf _snprintf
#endif
///////////////////////////////////////////////////////////////////////////////
namespace test {
///////////////////////////////////////////////////////////////////////////////
static const char* KFname = "sample-plain.txt";

QByteArray
createSourceData(size_t size) {
    QByteArray arr;
    // put a lot of test data
    QTextStream stream(&arr);
    stream << "Sample content for testing polarSSL library implementation in Qt5."
           << "\nby Amir Zamani <azadkuh@live.com>, @20150209"
           << "\n\nsome more data (to make this file larger than 4KB):\n\n";

    for ( size_t i = 0;    i < size;    i++ ) {
        char buffer[33] = {0};
        snprintf(buffer, 32, "%04lu: polarssl\n", i+1);
        stream << buffer;
    }

    stream.flush();
    return arr;
}

int
createSourceFile(const QByteArray& src) {
    QFile f(filePath());
    if ( !f.open(QFile::WriteOnly) ) {
        qCritical("file creation failed: %s", KFname);
        return -1;
    }

    f.write(src);
    return 0;
}

QString
filePath() {
    return QFileInfo(QCoreApplication::applicationDirPath(),
                     KFname)
            .absoluteFilePath();
}

QByteArray
readFromFile(const QString &fileName) {
    QString filePath = fileName;
    if ( !fileName.startsWith(":/") )
        filePath = QFileInfo(QCoreApplication::applicationDirPath(),
                             fileName).absoluteFilePath();

    QFile f(filePath);

    if ( f.open(QFile::ReadOnly) ) {
        return f.readAll();
    }

    return QByteArray();
}

bool
writeToFile(const QString& fileName, const QByteArray& data) {
    QFile f(QFileInfo(QCoreApplication::applicationDirPath(),
                      fileName).absoluteFilePath());

    if ( f.open(QFile::WriteOnly) ) {
        f.write( data );
        return true;
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////////
} // namespace test
///////////////////////////////////////////////////////////////////////////////
