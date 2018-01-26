# -*-Makefile-*-

SUBDIRS += svm
SVM_OBJS = svm-esm.o svm-esmb.o svm-crypto.o svm-fdt.o svm-rtas.o
SVM_OBJS += svm-rtas-bbuf.o svm-rtas-hdlr.o svm-pagemap.o svm-pagemap-test.o
SVM_OBJS += svm-tss.o

SVM=svm/built-in.a

$(SVM): $(SVM_OBJS:%=svm/%)
