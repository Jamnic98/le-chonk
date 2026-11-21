       IDENTIFICATION DIVISION.
       PROGRAM-ID. PAYROLL.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-DB-PASSWORD          PIC X(20) VALUE "Pr0dP@ss!2024".
       01  WS-USER-ID              PIC X(10).
       01  WS-QUERY                PIC X(200).
       01  WS-SSN                  PIC X(9).
       01  WS-SALARY               PIC 9(7)V99.
       PROCEDURE DIVISION.
       MAIN-PARA.
           MOVE "admin" TO WS-USER-ID.
           EXEC SQL
               CONNECT TO PAYDB USER admin USING :WS-DB-PASSWORD
           END-EXEC.
           ACCEPT WS-USER-ID FROM CONSOLE.
           STRING "SELECT SSN, SALARY FROM EMP WHERE ID = '"
                  DELIMITED SIZE
                  WS-USER-ID DELIMITED SIZE
                  "'" INTO WS-QUERY.
           EXEC SQL
               PREPARE Q1 FROM :WS-QUERY
           END-EXEC.
           EXEC SQL
               EXECUTE Q1 INTO :WS-SSN, :WS-SALARY
           END-EXEC.
           DISPLAY "SSN: " WS-SSN.
           DISPLAY "SALARY: " WS-SALARY.
           STOP RUN.
