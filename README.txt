Implementaţi un shell cu urmatoarele functionalitati:
- accepta comanda interna 'exit';
- accepta comenzi externe cu un numar oarecare de argumente;
- accepta filtre de comenzi externe; filtrul poate avea un numar oarecare de
componente iar comenzile pot avea un numar oarecare de argumente si pot contine
redirectari catre fisiere, de forma 'nr>', 'nr>>', 'nr<', '>', '>>', '<'
(se redirecteaza descriptorul 'nr', care, prin lipsa, este 0 la '<' si 1
la '>' si '>>'); redirectarile au precedenta fata de '|'.
 Se va lucra doar in limbajul C, fara a se apela direct sau indirect la
shell-ul din sistem.
