#' Returns a sample of the data sets based on the percentage provided by `n` parameter.
#' You can also set the random seed for reproducible samples.
#'
#' @param n Percentage of the sample data set. Values from 0 < n < 1. Default set as 0.1
#' @param rnd.seed Random seed for sample selection. Default set at 1714.
#'
#' @return list of data frames (cves, cpes, cwes, capec, sard)
#' @export
#'
#' @examples
GetSampleDataSet <- function(n = 0.1, rnd.seed = 1714) {
  if ((0 >= n) || (n >= 1)) n = 0.1
  set.seed(seed = rnd.seed)
  # system.file("extdata", "netsec-full.rda", package = "graph.security")
  netsec <- list(cves = netsec.data$datasets$cves[sample(x = nrow(netsec.data$datasets$cves), size = round(n*nrow(netsec.data$datasets$cves))), ],
                 cpes = netsec.data$datasets$cpes[sample(x = nrow(netsec.data$datasets$cpes), size = round(n*nrow(netsec.data$datasets$cpes))), ],
                 cwes = netsec.data$datasets$cwes[sample(x = nrow(netsec.data$datasets$cwes), size = round(n*nrow(netsec.data$datasets$cwes))), ],
                 capec = netsec.data$datasets$capec[sample(x = nrow(netsec.data$datasets$capec), size = round(n*nrow(netsec.data$datasets$capec))), ],
                 sard = netsec.data$datasets$sard[sample(x = nrow(netsec.data$datasets$sard), size = round(n*nrow(netsec.data$datasets$sard))), ])
  # TODO: Reducing factors levels to new size should optimize data frame.
  return(netsec)
}

GetRelationCVE2CWE <- function() {
  c.cwes <- sapply(netsec.data$datasets$cves$problem.type, function(x) length(jsonlite::fromJSON(x)))

  # No edges
  cves2cwes0 <- netsec.data$datasets$cves[c.cwes == 0, c("cve.id", "problem.type", "cvss2.score", "cvss3.score")]
  names(cves2cwes0) <- c("src", "target", "cvss2.score", "cvss3.score")
  cves2cwes0$cvss2.score[is.na(cves2cwes0$cvss2.score)] <- 0
  cves2cwes0$cvss3.score[is.na(cves2cwes0$cvss3.score)] <- 0
  cves2cwes0 <- dplyr::mutate(cves2cwes0, risk = pmax(cvss2.score, cvss3.score))
  cves2cwes0$cvss2.score <- NULL
  cves2cwes0$cvss3.score <- NULL
  cves2cwes0$target <- rep("NVD-CWE-noinfo", nrow(cves2cwes0))

  # One edge
  cves2cwes1 <- netsec.data$datasets$cves[c.cwes == 1, c("cve.id", "problem.type", "cvss2.score", "cvss3.score")]
  cves2cwes1$problem.type <- sapply(cves2cwes1$problem.type, function(x) jsonlite::fromJSON(x))
  names(cves2cwes1) <- c("src", "target", "risc2", "risc3")
  cves2cwes1$risc2[is.na(cves2cwes1$risc2)] <- 0
  cves2cwes1$risc3[is.na(cves2cwes1$risc3)] <- 0
  cves2cwes1 <- dplyr::mutate(cves2cwes1, risk = pmax(risc2, risc3))
  cves2cwes1$risc2 <- NULL
  cves2cwes1$risc3 <- NULL

  # Multiple edges
  cves2cwesN <- netsec.data$datasets$cves[c.cwes > 1, c("cve.id", "problem.type", "cvss2.score", "cvss3.score")]
  cves2cwesN$cvss2.score[is.na(cves2cwesN$cvss2.score)] <- 0
  cves2cwesN$cvss3.score[is.na(cves2cwesN$cvss3.score)] <- 0
  cves2cwesN <- dplyr::mutate(cves2cwesN, risk = pmax(cvss2.score, cvss3.score))
  cves2cwesN$cvss2.score <- NULL
  cves2cwesN$cvss3.score <- NULL
  cves2cwesN <- apply(cves2cwesN, 1,
                      function(x) {
                        pt <- jsonlite::fromJSON(x[["problem.type"]])
                        cve <- rep(x[["cve.id"]], length(pt))
                        data.frame(src = cve, target = pt, risk = as.numeric(x[["risk"]]),
                                   stringsAsFactors = F)
                      })
  cves2cwesN <- data.table::rbindlist(cves2cwesN)
  # Join edges
  cves2cwes <- dplyr::bind_rows(cves2cwes0, cves2cwes1, cves2cwesN)

  return(cves2cwes)
}

GetRelationCWE2CAPEC <- function() {
  netsec.data$datasets$cwes$Related_Attack_Patterns[is.na(netsec.data$datasets$cwes$Related_Attack_Patterns)] <- "{}"
  c.capec <- sapply(netsec.data$datasets$cwes$Related_Attack_Patterns, function(x) length(jsonlite::fromJSON(x)))
  # One edge
  cwes2capec1 <- netsec.data$datasets$cwes[c.capec == 1, c("Code_Standard", "Related_Attack_Patterns")]
  cwes2capec1$Related_Attack_Patterns <- as.character(sapply(cwes2capec1$Related_Attack_Patterns, function(x) jsonlite::fromJSON(x)))
  names(cwes2capec1) <- c("src", "target")

  # Multiple edges
  cwes2capecN <- netsec.data$datasets$cwes[c.capec > 1, c("Code_Standard", "Related_Attack_Patterns")]
  cwes2capecN <- apply(cwes2capecN, 1,
                       function(x) {
                         capec <- as.character(jsonlite::fromJSON(x[["Related_Attack_Patterns"]]))
                         cwe <- rep(x[["Code_Standard"]], length(capec))
                         data.frame(src = cwe, target = capec, stringsAsFactors = F)
                       })
  cwes2capecN <- data.table::rbindlist(cwes2capecN)
  # Join edges
  cwes2capec <- dplyr::bind_rows(cwes2capec1, cwes2capecN)
  cwes2capec$target <- as.character(sapply(cwes2capec$target, function(x) paste("CAPEC", x, sep = "-")))

  return(cwes2capec)
}

GetScopeInSankeyNetwork <- function(scope = c("CVE-2016-8475", "CVE-2014-8613", "CVE-2008-4915", "CVE-2017-3045")) {
  # scope <- netsec.data$datasets$cves$cve.id[sample(nrow(netsec.data$datasets$cves), 50)]
  cves2cwes <- GetRelationCVE2CWE()
  scope.cve2cwe <- dplyr::filter(cves2cwes, src %in% scope)
  if (!(any(scope %in% cves2cwes$src))) {
    scope.cve <- data.frame(src = scope[which(!(scope %in% cves2cwes$src))],
                            target = "NVD-CWE-noinfo", stringsAsFactors = F)
    scope.cve2cwe <- dplyr::bind_rows(scope.cve2cwe, scope.cve)
  }
  nodes.list <- unique(c(scope.cve2cwe$src, scope.cve2cwe$target))
  nodes <- data.frame(name = nodes.list, id = 0:(length(nodes.list) - 1), stringsAsFactors = F)


  links.source <- dplyr::select(dplyr::left_join(scope.cve2cwe, nodes, by = c("src" = "name")), id)
  names(links.source) <- c("source")
  links.target <- dplyr::select(dplyr::left_join(scope.cve2cwe, nodes, by = c("target" = "name")), id, risk)
  names(links.target) <- c("target", "risk")
  links <- dplyr::bind_cols(links.source, links.target)

  scopeSN <- list(nodes = nodes, links = links)
  networkD3::sankeyNetwork(Links = scopeSN$links, Nodes = scopeSN$nodes, Source = "source",
                Target = "target", Value = "risk", NodeID = "name",
                units = "Risk", fontSize = 12, nodeWidth = 30)
}

GetNetworkData <- function(scope = c("CVE-2016-8475", "CVE-2014-8613", "CVE-2008-4915")) {
  # scope <- netsec.data$datasets$cves$cve.id[sample(nrow(netsec.data$datasets$cves), 50)]

  # CVEs --> CWEs
  cves2cwes <- GetRelationCVE2CWE()

  # CWEs --> CAPECs
  cwes2capec <- GetRelationCWE2CAPEC()

  # CWEs hierarcy
  cwes.hr <- GetCWEHierarcy()

  # View 1008:Architectural Concepts
  # View 928:Weaknesses in OWASP Top Ten 2013
  # View 919:Weaknesses in Mobile Applications
  v2d <- (dplyr::select(dplyr::filter(dplyr::filter(cwes,
                                                    CWE_Type == "View"),
                                      ID != "1008"),
                        ID))[["ID"]]
  v2v <- (dplyr::select(dplyr::filter(dplyr::filter(cwes,
                                                    CWE_Type == "View"),
                                      ID == "1008"),
                        ID))[["ID"]]
  c2v <- (dplyr::select(dplyr::filter(dplyr::filter(cwes,
                                                    CWE_Type == "Category"),
                                      ID == "1008"),
                        ID))[["ID"]]
  cwes.hr$target %in% v2d

  # CWEs --> CWEs (father)

  # CWEs group by View --> clusters

  # Filter scope
  scope.cve.cwe <- dplyr::filter(cves2cwes, src %in% scope)
  if (any(scope %in% cves2cwes$src)) {
    scope.cves2cwes <- scope.cve.cwe
  } else {
    scope.cve <- data.frame(src = scope[which(!(scope %in% cves2cwes$src))],
                            target = "NVD-CWE-noinfo", stringsAsFactors = F)
    scope.cves2cwes <- dplyr::bind_rows(scope.cve.cwe, scope.cve)
  }


  scope <- unique(cwes2capec$target)
  scope.cwe.capec <- dplyr::filter(cwes2capec, src %in% scope)
  scope.cwe <- data.frame(src = scope[which(!(scope %in% cwes2capec$src))],
                          target = "NVD-CWE-noinfo", stringsAsFactors = F)
  cwes2capec <- dplyr::bind_rows(scope.cwe.capec, scope.cwe)

  # CVEs --> CPEs
  # cves <- netsec.data$datasets$cves
  # cves2cpes <- cves[, c("cve.id", "vulnerable.configuration")]
  # for (i in 1:nrow(cves2cpes)) {
  #   vcpes <- jsonlite::fromJSON(cves2cpes$vulnerable.configuration[i])
  #   if (vcpes$operator == "OR") {
  #     vcpes <- vcpes$cpe[[1]]
  #     vcpes <- vcpes[vcpes$vulnerable, "cpe23Uri"]
  #   }
  #   cves2cpes$vulnerable.configuration[i] <- vcpes
  # }



  # Join all graphs
  gsec <- dplyr::bind_rows(cves2cwes, cwes2capec)
  return(cves2cwes)
}

#' Given a net.security CWES data.frame it returns a data.frame prepared for
#' network representation of CWE relationships as edges. The columns are:
#'     - src: Source CWE ID
#'     - target: Target CWE ID
#'     - nature: Type of relationship
#'     - weight: Experimental value representing the "force" of the relationship
#'
#' Type of relationship explanation from CWE official schema:
#' The RelatedNatureEnumeration simple type defines the different values that
#' can be used to define the nature of a related weakness.
#'   - A ChildOf nature denotes a related weakness at a higher level of abstraction.
#'   - A ParentOf nature denotes a related weakness at a lower level of abstraction.
#'   - The StartsWith, CanPrecede, and CanFollow relationships are used
#'     to denote weaknesses that are part of a chaining structure.
#'   - The RequiredBy and Requires relationships are used to denote a weakness that
#'     is part of a composite weakness structure.
#'   - The CanAlsoBe relationship denotes a weakness that, in the proper
#'     environment and context, can also be perceived as the target weakness.
#'     Note that the CanAlsoBe relationship is not necessarily reciprocal.
#'   - The PeerOf relationship is used to show some similarity with the target weakness
#'     that does not fit any of the other type of relationships.
#'
#' The RelationshipsType complex type provides elements to show the associated
#' relationships with a given view or category.
#'   - The Member_Of element is used to denote the individual categories that are included
#'     as part of the target view.
#'   - The Has_Member element is used to define the weaknesses or other
#'     categories that are grouped together by a category.
#' In both cases, the required CWE_ID attribute specifies the unique CWE ID that
#' is the target entry of the relationship, while the View_ID specifies which view
#' the given relationship is relevant to.
#'
#' @param cwes data.frame, from net.security data sets
#' @param as_numbers if TRUE src and target are numbers, if FALSE as character starting with "CWE-"
#'
#' @return data.frame
#' @export
#'
#' @examples
GetCWEHierarcy <- function(as_numbers = T) {
  cwes.weaknesses <- netsec.data$datasets$cwes[netsec.data$datasets$cwes$CWE_Type == "Weakness", ]
  cwes.categories <- netsec.data$datasets$cwes[netsec.data$datasets$cwes$CWE_Type == "Category", ]
  cwes.views <- netsec.data$datasets$cwes[netsec.data$datasets$cwes$CWE_Type == "View", ]

  # Experimental relationship weight

  rw <- c("ChildOf" = 3,
          "ParentOf" = 3,
          "StartsWith" = 5,
          "CanFollow" = 4,
          "CanPrecede" = 4,
          "RequiredBy" = 7,
          "Requires" = 7,
          "CanAlsoBe" = 5,
          "PeerOf" = 1,
          "has_member" = 5,
          "member_of" = 5)

  # Views hierarchy
  vh <- cwes.views[, c("ID", "Related_Weakness")]
  vh$Related_Weakness[is.na(vh$Related_Weakness)] <- "{}"
  vh <- apply(vh, 1,
               function(x) {
                 y <- RJSONIO::fromJSON(x[2])
                 if (length(y) > 0) {
                   y <- cbind(as.data.frame(t(as.matrix(as.data.frame(y))), stringsAsFactors = F),
                              data.frame(nature = row.names(as.matrix(y)), stringsAsFactors = F))
                   y$cwe_id <- as.character(y$cwe_id)
                   y$view_id <- as.character(y$view_id)
                   data.table::rbindlist(apply(y, 1,
                                               function(z){
                                                 if (z["nature"] == "has_member") {
                                                   src <- z["cwe_id"]
                                                   target <- x[1]
                                                 } else {
                                                   src <- x[1]
                                                   target <- z["cwe_id"]
                                                 }
                                                 nature <- z["nature"]
                                                 data.frame(src = src,
                                                            target = target,
                                                            nature = nature,
                                                            weight = rw[nature],
                                                            stringsAsFactors = F)
                                               }
                   ))
                 } else {
                   data.frame(src = x[1], target = NA,
                              nature = NA, weight = 0, stringsAsFactors = F)
                 }
               }
  )
  vh <- unique(data.table::rbindlist(vh))
  vh$type <- rep("view", nrow(vh))

  # Categories hierarchy
  ch <- cwes.categories[, c("ID", "Related_Weakness")]
  ch$Related_Weakness[is.na(ch$Related_Weakness)] <- "{}"
  ch <- apply(ch, 1,
               function(x) {
                 y <- RJSONIO::fromJSON(x[2])
                 if (length(y) > 0) {
                   y <- cbind(as.data.frame(t(as.matrix(as.data.frame(y))), stringsAsFactors = F),
                              data.frame(nature = row.names(as.matrix(y)), stringsAsFactors = F))
                   y$cwe_id <- as.character(y$cwe_id)
                   y$view_id <- as.character(y$view_id)
                   data.table::rbindlist(apply(y, 1,
                                               function(z){
                                                 if (z["nature"] == "has_member") {
                                                   src <- z["cwe_id"]
                                                   target <- x[1]
                                                 } else {
                                                   src <- x[1]
                                                   target <- z["cwe_id"]
                                                 }
                                                 nature <- z["nature"]
                                                 data.frame(src = src,
                                                            target = target,
                                                            nature = nature,
                                                            weight = rw[nature],
                                                            stringsAsFactors = F)
                                               }
                   ))
                 } else {
                   data.frame(src = x[1], target = NA,
                              nature = NA, weight = 0, stringsAsFactors = F)
                 }
               }
  )
  ch <- unique(data.table::rbindlist(ch))
  ch$type <- rep("category", nrow(ch))

  # Weakness hierarchy
  wh <- cwes.weaknesses[, c("ID", "Related_Weakness")]
  wh$Related_Weakness[is.na(wh$Related_Weakness)] <- "{}"
  wh <- apply(wh, 1,
              function(x) {
                y <- RJSONIO::fromJSON(x[2])
                data.table::rbindlist(lapply(y,
                                             function(z) {
                                               data.frame(src = x[1],
                                                          target = z[["cwe_id"]],
                                                          nature = z[["nature"]],
                                                          weight = rw[(z[["nature"]])],
                                                          stringsAsFactors = F)
                                             }
                ))

              }
  )
  wh <- unique(data.table::rbindlist(wh))
  wh$type <- rep("weakness", nrow(wh))

  cwes2cwes <- dplyr::bind_rows(vh, ch, wh)
  if (as_numbers) {
    cwes2cwes$src <- as.numeric(cwes2cwes$src)
    cwes2cwes$target <- as.numeric(cwes2cwes$target)
  } else {
    cwes2cwes$src <- as.character(sapply(cwes2cwes$src, function(x) paste("CWE", x, sep = "-")))
    cwes2cwes$target <- as.character(sapply(cwes2cwes$target, function(x) paste("CWE", x, sep = "-")))
  }
  cwes2cwes$nature <- as.factor(cwes2cwes$nature)
  attributes(cwes2cwes)[[".internal.selfref"]] <- NULL

  return(cwes2cwes)
}

#' References
#' https://christophergandrud.github.io/networkD3/
#' http://kateto.net/networks-r-igraph
#'